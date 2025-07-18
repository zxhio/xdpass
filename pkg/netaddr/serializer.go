package netaddr

import "encoding/json"

type setT interface {
	Set(s string) error
}

type strT interface {
	String() string
}

func unmarshal[T setT](v T, data []byte) error {
	var s string
	err := json.Unmarshal(data, &s)
	if err != nil {
		return err
	}
	return v.Set(s)
}

func marshal[T strT](v T) ([]byte, error) {
	return json.Marshal(v.String())
}
