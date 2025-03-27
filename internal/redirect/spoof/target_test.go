package spoof

import (
	"encoding/json"
	"testing"
)

func TestTarget(t *testing.T) {
	tgt := TargetARPReply{}
	data, err := json.Marshal(tgt)
	if err != nil {
		t.Fatal(err)
	}
	t.Log(string(data))
}
