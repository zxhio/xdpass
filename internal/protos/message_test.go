package protos

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestType(t *testing.T) {
	var v = struct {
		T Type `json:"type"`
	}{
		T: Type_Redirect,
	}
	data, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, []byte(`{"type":"redirect"}`), data)

	err = json.Unmarshal([]byte(`{"type":"filter"}`), &v)
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, v.T, Type_Filter)

	// Invalid type
	err = json.Unmarshal([]byte(`{"type":"foo"}`), &v)
	assert.NotEqual(t, err, nil)
}
