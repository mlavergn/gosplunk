package gosplunk

import (
	"bufio"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"io"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Version export
const Version = "0.1.0"

// -----------------------------------------------------------------------------

// HTTPClient type
type HTTPClient struct {
	Client *http.Client
}

var httpClient *http.Client
var tlsConfigOnce sync.Once
var tlsConfig *tls.Config

// NewHTTPClient init
func NewHTTPClient(timeout time.Duration) *HTTPClient {
	// only need to configure tls.Config once
	tlsConfigOnce.Do(func() {
		rootCAs, _ := x509.SystemCertPool()
		if rootCAs == nil {
			rootCAs = x509.NewCertPool()
		}

		// currently based on Linux CA location
		caCert, err := ioutil.ReadFile("/etc/ssl/ca-bundle.crt")
		if err == nil {
			rootCAs.AppendCertsFromPEM(caCert)
		}

		tlsConfig = &tls.Config{
			InsecureSkipVerify: true,
			RootCAs:            rootCAs,
		}
	})
	httpTransport := &http.Transport{
		TLSClientConfig: tlsConfig,
		DialContext: (&net.Dialer{
			Timeout: timeout,
		}).DialContext,
	}

	httpClient = &http.Client{
		Transport: httpTransport,
	}

	return &HTTPClient{
		Client: httpClient,
	}
}

// -----------------------------------------------------------------------------
// Splunk

// SplunkPayload type
type SplunkPayload struct {
	Sourcetype string                 `json:"sourcetype"`
	Event      map[string]interface{} `json:"event"`
	Host       string                 `json:"host"`
	Source     string                 `json:"source"`
	Time       int64                  `json:"time"`
	Index      string                 `json:"index"`
}

// JSON helper
func (id *SplunkPayload) JSON() []byte {
	result, _ := json.Marshal(id)
	return result
}

var splunkHostname *string

// NewSplunkPayload init
func NewSplunkPayload(index string, event map[string]interface{}) *SplunkPayload {
	if splunkHostname == nil {
		hostname, _ := os.Hostname()
		splunkHostname = &hostname
	}
	return &SplunkPayload{
		Sourcetype: "json",
		Event:      event,
		Host:       *splunkHostname,
		Source:     "json",
		Time:       time.Now().UTC().Unix(),
		Index:      index,
	}
}

// Splunk type
type Splunk struct {
	reader *io.PipeReader
	writer *bufio.Writer
	token  string
	root   string
}

// NewSplunk init
func NewSplunk(root string, token string) *Splunk {
	// bufio
	reader, rwriter := io.Pipe()
	writer := bufio.NewWriterSize(rwriter, 4096)
	id := &Splunk{
		reader: reader,
		writer: writer,
		token:  token,
		root:   root,
	}
	return id
}

func (id *Splunk) log(index string, arg ...string) {
	epoch := strconv.FormatInt(time.Now().UTC().Unix(), 10)
	args := strings.Join(arg, " ")
	payload := []string{epoch, "INFO", args}
	// log.Printf("%s\t%s\t%s", payload[0], payload[1], payload[2])
	id.flush(index, [][]string{payload})
}

// TO BE TESTED: may block thread
func (id *Splunk) proxy(index string, entry map[string]interface{}) {
	payload := NewSplunkPayload(index, entry)
	data := payload.JSON()

	if id.writer.Available() <= len(data) {
		id.writer.Flush()
		id.send(id.reader)
	}

	id.writer.Write(data)
}

func (id *Splunk) record(index string, timestamp int64, data []byte) {
	reader, writer := io.Pipe()
	defer reader.Close()

	var event map[string]interface{}
	json.Unmarshal(data, &event)
	payload := NewSplunkPayload(index, event)

	go func() {
		defer writer.Close()
		writer.Write(payload.JSON())
	}()

	id.send(reader)
}

func (id *Splunk) flush(index string, logs [][]string) {
	reader, writer := io.Pipe()

	go func() {
		defer writer.Close()
		for _, log := range logs {
			ts, _ := strconv.ParseInt(log[1], 10, 64)
			message := strings.Join(log[2:], " ")
			payload := NewSplunkPayload(index, map[string]interface{}{
				"timestamp": ts,
				"level":     log[0],
				"message":   message,
			})
			writer.Write(payload.JSON())
		}
	}()

	id.send(reader)
}

func (id *Splunk) send(reader *io.PipeReader) bool {
	defer reader.Close()
	client := NewHTTPClient(2 * time.Second).Client

	req, err := http.NewRequest(http.MethodPost, id.root+"/services/collector/event", reader)
	if err != nil {
		log.Println("Splunk failed create request", err)
		return false
	}

	req.Header.Add("Authorization", "Splunk "+id.token)
	req.Header.Add("Content-Type", "application/json")
	req.Header.Add("Connection", "close")

	resp, rerr := client.Do(req)
	if rerr != nil {
		log.Println("Splunk failed to post events", err)
		return false
	}
	defer resp.Body.Close()

	return true
}
