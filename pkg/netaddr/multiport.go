package netaddr

import (
	"encoding/json"
	"slices"
	"strconv"
	"strings"
)

// MultiPort e.g. 80,81
type MultiPort []uint16

func (MultiPort) Type() string {
	return "MultiPort"
}

func (p MultiPort) String() string {
	s := make([]string, 0, len(p))
	for _, v := range p {
		s = append(s, strconv.Itoa(int(v)))
	}
	return strings.Join(s, ",")
}

func (p *MultiPort) Set(s string) error {
	if strings.TrimSpace(s) == "" {
		*p = MultiPort{}
		return nil
	}

	ports := []uint16{}
	fields := strings.Split(s, ",")
	for _, field := range fields {
		port, err := strconv.Atoi(field)
		if err != nil {
			return err
		}
		if !slices.Contains(ports, uint16(port)) {
			ports = append(ports, uint16(port))
		}
	}

	*p = MultiPort(ports)
	return nil
}

func (p MultiPort) Compare(other MultiPort) int {
	return slices.Compare(p, other)
}

func (p MultiPort) MarshalJSON() ([]byte, error) {
	return json.Marshal(p.String())
}

func (p *MultiPort) UnmarshalJSON(data []byte) error {
	return unmarshal(p, data)
}

func NewMultiPort(s string) (MultiPort, error) {
	var r MultiPort
	return r, r.Set(s)
}
