package netaddr

import (
	"encoding/json"
	"fmt"
	"net"
	"strconv"
	"strings"
)

type RangeT[T uint16 | uint32 | IPv4Addr] struct {
	Start T `json:"start,omitempty"`
	End   T `json:"end,omitempty"`
}

func (r RangeT[T]) Contains(v T) bool {
	return v >= r.Start && v <= r.End
}

func (r RangeT[T]) Compare(other RangeT[T]) int {
	if r.Start < other.Start {
		return -1
	}
	if r.Start > other.Start {
		return 1
	}
	if r.End < other.End {
		return -1
	}
	if r.End > other.End {
		return 1
	}
	return 0
}

// IPv4Range e.g. 192.168.10.10-192.168.10.20
type IPv4Range RangeT[IPv4Addr]

func (r IPv4Range) Contains(v IPv4Addr) bool {
	return RangeT[IPv4Addr](r).Contains(v)
}

func (r IPv4Range) Compare(other IPv4Range) int {
	return RangeT[IPv4Addr](r).Compare(RangeT[IPv4Addr](other))
}

func (IPv4Range) Type() string {
	return "IPv4Range"
}

func (r IPv4Range) String() string {
	if r.Start == r.End {
		if r.Start == 0 {
			return ""
		}
		return r.Start.String()
	}
	return fmt.Sprintf("%s-%s", r.Start.String(), r.End.String())
}

func (r *IPv4Range) Set(s string) error {
	var (
		start IPv4Addr
		end   IPv4Addr
	)

	fields := strings.Split(s, "-")
	if len(fields) != 1 && len(fields) != 2 {
		return fmt.Errorf("invalid iprange: %s", s)
	}

	if len(fields) >= 1 {
		ip := net.ParseIP(fields[0])
		if ip == nil {
			return fmt.Errorf("invalid start ip: %s", fields[0])
		}
		start = NewIPv4AddrFromIP(ip)
		end = start

		if len(fields) == 2 {
			ip := net.ParseIP(fields[1])
			if ip == nil {
				return fmt.Errorf("invalid end ip: %s", fields[1])
			}
			end = NewIPv4AddrFromIP(ip)
		}
	}

	r.Start = start
	r.End = end

	return nil
}

func (r IPv4Range) MarshalJSON() ([]byte, error) {
	return json.Marshal(r.String())
}

func (r *IPv4Range) UnmarshalJSON(data []byte) error {
	return unmarshal(r, data)
}

func NewIPv4Range(s string) (IPv4Range, error) {
	var r IPv4Range
	return r, r.Set(s)
}

// PortRange e.g. 80, 80:90, 80-90
type PortRange RangeT[uint16]

func (r PortRange) Contains(v uint16) bool {
	return RangeT[uint16](r).Contains(v)
}

func (r PortRange) Compare(other PortRange) int {
	return RangeT[uint16](r).Compare(RangeT[uint16](other))
}

func (PortRange) Type() string {
	return "PortRange"
}

func (r PortRange) String() string {
	if r.Start == r.End {
		return strconv.Itoa(int(r.Start))
	}
	return fmt.Sprintf("%d:%d", r.Start, r.End)
}

func (r *PortRange) Set(s string) error {
	var (
		fields []string
		start  uint16
		end    uint16
	)

	if strings.IndexByte(s, ':') != -1 {
		fields = strings.Split(s, ":")
	} else if strings.IndexByte(s, '-') != -1 {
		fields = strings.Split(s, "-")
	} else {
		fields = []string{s}
	}
	if len(fields) != 1 && len(fields) != 2 {
		return fmt.Errorf("invalid portrange: %s", s)
	}

	if len(fields) >= 1 {
		port, err := strconv.Atoi(fields[0])
		if err != nil {
			return fmt.Errorf("invalid start port: %s", fields[0])
		}
		start = uint16(port)
		end = start

		if len(fields) == 2 {
			port, err := strconv.Atoi(fields[1])
			if err != nil {
				return fmt.Errorf("invalid end port: %s", fields[1])
			}
			end = uint16(port)
		}
	}

	if start > end {
		return fmt.Errorf("invalid end port: %d, less than start: %d", end, start)
	}
	r.Start = start
	r.End = end
	return nil
}

func (r PortRange) MarshalJSON() ([]byte, error) {
	return json.Marshal(r.String())
}

func (r *PortRange) UnmarshalJSON(data []byte) error {
	return unmarshal(r, data)
}

func NewPortRange(s string) (PortRange, error) {
	var r PortRange
	return r, r.Set(s)
}
