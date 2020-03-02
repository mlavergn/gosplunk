package main

import (
	"strconv"
	"time"

	"github.com/mlavergn/gosplunk"
)

var rootURL = "https://foo.splunk-indexer.example.com:8088"
var token = "splunkto-kens-houl-bepl-acedintohere"
var index = "demo"

func main() {
	splunk := gosplunk.NewSplunk(rootURL, token, index, 4096)

	for i := 0; i < 100; i++ {
		splunk.LogStrings(gosplunk.SplunkLog.Info, "gosplunk", "test", strconv.Itoa(i))
	}

	<-time.After(1 * time.Minute)
}
