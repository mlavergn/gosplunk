package gosplunk

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"io"
	"io/ioutil"
	"log"
	oslog "log"
	"net"
	"net/http"
	"os"
	"strings"
	"time"
)

// Version export
const Version = "0.2.0"

// logger stand-in
var dlog *oslog.Logger

// DEBUG toggle
var DEBUG = false

// -----------------------------------------------------------------------------

var splunkShared struct {
	// http.Client is threadsafe and can be reused
	http *http.Client
}

// init setup the http transport
func init() {
	if DEBUG {
		dlog = oslog.New(os.Stderr, "GoSplunk ", oslog.Ltime|oslog.Lshortfile)
	} else {
		dlog = oslog.New(ioutil.Discard, "", 0)
	}

	rootCAs, _ := x509.SystemCertPool()
	if rootCAs == nil {
		rootCAs = x509.NewCertPool()
	}

	// currently based on Linux CA location
	caCert, err := ioutil.ReadFile("/etc/ssl/ca-bundle.crt")
	if err == nil {
		rootCAs.AppendCertsFromPEM(caCert)
	}

	tlsConfig := &tls.Config{
		InsecureSkipVerify: true,
		RootCAs:            rootCAs,
	}

	httpTransport := &http.Transport{
		TLSClientConfig: tlsConfig,
		DialContext: (&net.Dialer{
			Timeout: 5 * time.Second,
		}).DialContext,
	}

	splunkShared.http = &http.Client{
		Transport: httpTransport,
	}
}

// -----------------------------------------------------------------------------

// LogLevel export
type LogLevel string

func (id LogLevel) String() string {
	return string(id)
}

type logLevels struct {
	Debug LogLevel
	Info  LogLevel
	Warn  LogLevel
	Error LogLevel
	Fatal LogLevel
	Off   LogLevel
}

// SplunkLog export
var SplunkLog = logLevels{
	Info:  "INFO",
	Warn:  "WARN",
	Error: "ERROR",
	Fatal: "FATAL",
	Off:   "OFF",
}

// -----------------------------------------------------------------------------
// SplunkPayload

// SplunkPayload type
type SplunkPayload struct {
	Time       int64                  `json:"time"`
	Host       string                 `json:"host"`
	Index      string                 `json:"index"`
	Source     string                 `json:"source"`
	Sourcetype string                 `json:"sourcetype"`
	Event      map[string]interface{} `json:"event"`
}

// NewSplunkPayload init
func NewSplunkPayload(index string, host string, event map[string]interface{}) *SplunkPayload {
	id := &SplunkPayload{
		Time:       time.Now().UTC().Unix(),
		Host:       host,
		Index:      index,
		Source:     "json",
		Sourcetype: "json",
		Event:      event,
	}

	if len(id.Host) == 0 {
		id.Host, _ = os.Hostname()
	}
	return id
}

// JSON export
func (id *SplunkPayload) JSON() []byte {
	result, _ := json.Marshal(id)
	return result
}

// -----------------------------------------------------------------------------
// Splunk

// Splunk type
type Splunk struct {
	host      string
	index     string
	reader    *io.PipeReader
	writer    *io.PipeWriter
	bufWriter *bufio.Writer
	token     string
	rootURL   string
}

// NewSplunk init
func NewSplunk(rootURL string, token string, bufferSize int, index string) *Splunk {
	readPipe, writePipe := io.Pipe()
	writer := bufio.NewWriterSize(writePipe, bufferSize)
	id := &Splunk{
		reader:    readPipe,
		writer:    writePipe,
		bufWriter: writer,
		token:     token,
		rootURL:   rootURL,
		index:     index,
	}
	id.host, _ = os.Hostname()

	go func() {
		for true {
			<-time.After(1 * time.Second)
			id.Flush()
		}
	}()

	return id
}

// Log export
func (id *Splunk) Log(level LogLevel, args ...string) {
	dlog.Println("Splunk.Log")
	id.LogToIndex(id.index, id.host, level, args...)
}

// LogToIndex export
func (id *Splunk) LogToIndex(index string, host string, level LogLevel, args ...string) {
	dlog.Println("Splunk.LogToIndex")
	arg := strings.Join(args, " ")
	event := map[string]interface{}{
		"severity": level.String(),
		"message":  arg,
	}

	payload := NewSplunkPayload(id.index, id.host, event)
	id.bufWriter.Write(payload.JSON())
}

// Flush sends the log buffer to splunk for ingest
func (id *Splunk) Flush() {
	dlog.Println("Splunk.Flush")

	go func() {
		readLen := id.bufWriter.Buffered()
		if readLen == 0 {
			dlog.Println("Splunk.Flush no logs to flush")
			return
		}

		// http requires an EOF for POST, so setup a transient reader to provide an EOF
		buf := make([]byte, readLen)
		id.reader.Read(buf)
		payloadReader := bytes.NewReader(buf)

		id.send(payloadReader)
	}()

	ferr := id.bufWriter.Flush()
	if ferr != nil {
		log.Println("Splunk.Flush failed to flush", ferr)
		return
	}
}

// send posts payloads from the reader to splunk for ingest
func (id *Splunk) send(reader io.Reader) bool {
	dlog.Println("Splunk.send")

	url := id.rootURL + "/services/collector/event"
	req, err := http.NewRequest(http.MethodPost, url, reader)
	if err != nil {
		log.Println("Splunk failed create request", err)
		return false
	}

	req.Header.Add("Authorization", "Splunk "+id.token)
	req.Header.Add("Content-Type", "application/json")
	req.Header.Add("Connection", "close")

	resp, rerr := splunkShared.http.Do(req)
	if rerr != nil {
		log.Println("Splunk failed to post events", err)
		return false
	}
	defer resp.Body.Close()

	return true
}
