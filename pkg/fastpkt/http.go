package fastpkt

import (
	"bytes"
	"fmt"
	"net/http"
	"slices"
	"unsafe"
)

const (
	// HTTP method (Little-Endian)
	methodMagicGet     uint32 = 0x20544547 // "GET "
	methodMagicPost    uint32 = 0x54534f50 // "POST"
	methodMagicPut     uint32 = 0x20545550 // "PUT "
	methodMagicDelete  uint32 = 0x454c4544 // "DELE" (DELETE)
	methodMagicHead    uint32 = 0x44414548 // "HEAD"
	methodMagicOptions uint32 = 0x4954504f // "OPTI" (OPTIONS)
	methodMagicPatch   uint32 = 0x43544150 // "PATC" (PATCH)
	methodMagicConnect uint32 = 0x4e4e4f43 // "CONN" (CONNECT)
	methodMagicTrace   uint32 = 0x43415254 // "TRAC" (TRACE)
	methodMagicHTTP    uint32 = 0x50545448 // "HTTP"
)

var methodList = []string{
	http.MethodGet,
	http.MethodPost,
	http.MethodPut,
	http.MethodDelete,
	http.MethodHead,
	http.MethodOptions,
	http.MethodPatch,
	http.MethodConnect,
	http.MethodTrace,
}

// LazyHTTP zero memory alloc
type LazyHTTP struct {
	Decoded      bool
	Valid        bool
	VersionMajor uint8
	VersionMinor uint8
	Method       []byte
	URI          []byte
	Host         []byte
}

var emptyLazyHTTP LazyHTTP

func (h *LazyHTTP) Reset() {
	*h = emptyLazyHTTP
}

func (h *LazyHTTP) DecodeFromPacket(pkt *Packet) error {
	return h.DecodeFromData(pkt.RxData[pkt.L2Len+pkt.L3Len+pkt.L4Len:])
}

func (h *LazyHTTP) DecodeFromData(data []byte) error {
	h.Reset()
	h.Decoded = true

	// Decode request line
	idx := bytes.IndexByte(data, '\n')
	if idx < 0 {
		return fmt.Errorf("invalid http request line, no line breaks")
	}

	idx1 := bytes.IndexByte(data[:idx], ' ')
	idx2 := bytes.IndexByte(data[idx1+1:idx], ' ')
	if idx1 < 0 || idx2 < 0 {
		return fmt.Errorf("invalid http request line")
	}
	idx2 += idx1 + 1

	if !validMethod(data[:idx1]) {
		return fmt.Errorf("invalid http method: %s", string(data[:idx1]))
	}

	major, minor, ok := http.ParseHTTPVersion(b2s(data[idx2+1 : idx]))
	if !ok {
		return fmt.Errorf("invalid http version: '%s'", string(data[idx2+1:idx]))
	}

	// Decode request header Host
	idxHost := bytes.Index(data[idx:], []byte("Host:"))
	if idxHost != -1 {
		idxHost += idx + 5
		idxHostLine := bytes.IndexByte(data[idxHost+1:], '\n')
		if idxHostLine != -1 {
			idxHostLine += idxHost + 1
			h.Host = bytes.TrimSpace(data[idxHost+1 : idxHostLine])
		}
	}

	h.VersionMajor = uint8(major)
	h.VersionMinor = uint8(minor)
	h.Method = data[:idx1]
	h.URI = data[idx1+1 : idx2]
	h.Valid = true
	return nil
}

func validMethod(method []byte) bool {
	return slices.Contains(methodList, b2s(method))
}

func b2s(b []byte) string {
	if len(b) == 0 {
		return ""
	}
	return unsafe.String(&b[0], len(b))
}

// func s2b(s string) []byte { return unsafe.Slice(unsafe.StringData(s), len(s)) }
