package gosplunk

import (
	"log"
	"os"
	"strings"
	"testing"
)

func TestSplunkPayload(t *testing.T) {

	hostname, _ := os.Hostname()

	data := []string{"hello", "world"}
	message := strings.Join(data, " ")
	actualPayload := NewSplunkPayload("demo_idx", hostname, map[string]interface{}{
		"severity": SplunkLog.Debug.String(),
		"message":  message,
	})

	// JSON marshal -> unmarshal converts int to float
	expectedResult := map[string]interface{}{
		"time":       float64(actualPayload.Time),
		"host":       hostname,
		"index":      "demo_idx",
		"source":     "json",
		"sourcetype": "json",
		"event": map[string]interface{}{
			"severity": "DEBUG",
			"message":  "hello world",
		},
	}

	actualResult := actualPayload.Map()

	pass := true
	for k, v := range actualResult {
		if k != "event" && expectedResult[k] != v {
			pass = false
			t.Fatalf("Failed on key %s", k)
			log.Println(v)
			break
		}
	}

	if pass != true {
		t.Fatalf("Expected %v but got %v", expectedResult, actualResult)
	}
}
