package gosplunk

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
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
const Version = "0.2.1"

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
	Debug: "DEBUG",
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
	result, err := json.Marshal(id)
	if err != nil {
		log.Println("failed to marshal to JSON", err)
	}
	return result
}

// Map export
func (id *SplunkPayload) Map() map[string]interface{} {
	var result map[string]interface{}
	err := json.Unmarshal(id.JSON(), &result)
	if err != nil {
		log.Println("failed to unmarshal json intermediary", err)
	}
	return result
}

// -----------------------------------------------------------------------------
// Splunk

// Splunk type
type Splunk struct {
	host    string
	index   string
	token   string
	rootURL string
	writer  *bufio.Writer
}

// NewSplunk init
func NewSplunk(rootURL string, token string, index string, bufferSize int) *Splunk {
	id := &Splunk{
		token:   token,
		rootURL: rootURL,
		index:   index,
	}
	id.host, _ = os.Hostname()
	id.writer = bufio.NewWriterSize(id, bufferSize)

	// issue a flush every 15 seconds, regardless of there being any activity
	go func() {
		for true {
			<-time.After(15 * time.Second)
			id.writer.Flush()
		}
	}()

	return id
}

// LogStrings helper for logging string varargs
// NOTE: Assumes a convention of {severity: *, message: *}
// Uses the instance init index and host values
func (id *Splunk) LogStrings(level LogLevel, args ...string) {
	dlog.Println("Splunk.LogStrings")
	arg := strings.Join(args, " ")
	event := map[string]interface{}{
		"severity": level.String(),
		"message":  arg,
	}
	id.Log(id.index, id.host, event)
}

// LogEvent helper for logging string keyed maps
// Uses the instance init index and host values
func (id *Splunk) LogEvent(event map[string]interface{}) {
	dlog.Println("Splunk.LogEvent")
	id.Log(id.index, id.host, event)
}

// Log is the lowest-level exposed Splunk interface making no assumptions other
// than the instance endpoint and token
func (id *Splunk) Log(index string, host string, event map[string]interface{}) {
	dlog.Println("Splunk.Log")
	payload := NewSplunkPayload(index, host, event)
	id.writer.Write(payload.JSON())
}

// Write io.Writer API implementation
// will get called when buffer ceil hit or flish triggered
func (id *Splunk) Write(buffer []byte) (n int, err error) {
	dlog.Println("Splunk.Write", len(buffer))

	reader := bytes.NewReader(buffer)
	url := id.rootURL + "/services/collector/event"
	req, err := http.NewRequest(http.MethodPost, url, reader)
	if err != nil {
		log.Println("Splunk failed create request", err)
		return 0, err
	}

	req.Header.Add("Authorization", "Splunk "+id.token)
	req.Header.Add("Content-Type", "application/json")
	req.Header.Add("Connection", "close")

	resp, rerr := splunkShared.http.Do(req)
	if rerr != nil {
		log.Println("Splunk failed to post events", err)
		return 0, rerr
	}
	defer resp.Body.Close()

	return len(buffer), nil
}
