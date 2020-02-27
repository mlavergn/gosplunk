package main

import (
	"time"

	"github.com/mlavergn/gosplunk"
)

var rootURL = "https://foo.splunk-indexer.example.com:8088"
var token = "splunkto-kens-houl-bepl-acedintohere"
var index = "demo"

func main() {
	splunk := gosplunk.NewSplunk(rootURL, token, 4096, index)

	splunk.Log(gosplunk.SplunkLog.Info, "gosplunk", "testA")
	splunk.Log(gosplunk.SplunkLog.Info, "gosplunk", "testB")
	<-time.After(1 * time.Minute)
}
