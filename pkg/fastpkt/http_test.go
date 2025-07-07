package fastpkt

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestDecodePacketHTTP(t *testing.T) {
	testCases := []struct {
		content string
		l7proto uint8
	}{
		{http.MethodGet, L7ProtoHTTPReq},
		{http.MethodHead, L7ProtoHTTPReq},
		{http.MethodPost, L7ProtoHTTPReq},
		{http.MethodPut, L7ProtoHTTPReq},
		{http.MethodPatch, L7ProtoHTTPReq},
		{http.MethodDelete, L7ProtoHTTPReq},
		{http.MethodConnect, L7ProtoHTTPReq},
		{http.MethodOptions, L7ProtoHTTPReq},
		{http.MethodTrace, L7ProtoHTTPReq},
		{"HTTP", L7ProtoHTTPResp},
	}

	for _, tc := range testCases {
		var pkt Packet
		pkt.DecodePacketL7(append([]byte(tc.content), ' '))
		assert.Equal(t, tc.l7proto, pkt.L7Proto, tc.content)
	}
}

func TestDecodeLazyHTTP(t *testing.T) {
	testCases := []struct {
		content string
		lazy    LazyHTTP
	}{
		{
			"GET / HTTP/1.1\r\n",
			LazyHTTP{
				Decoded:      true,
				Valid:        true,
				VersionMajor: 1,
				VersionMinor: 1,
				Method:       []byte("GET"),
				URI:          []byte("/"),
			},
		},
		{
			"POST /foo HTTP/2.0\r\n",
			LazyHTTP{
				Decoded:      true,
				Valid:        true,
				VersionMajor: 2,
				VersionMinor: 0,
				Method:       []byte("POST"),
				URI:          []byte("/foo"),
			},
		},
		{
			"POST /foo HTTP/2.0\r\nHost: 192.168.110.200:5555\r\n",
			LazyHTTP{
				Decoded:      true,
				Valid:        true,
				VersionMajor: 2,
				VersionMinor: 0,
				Method:       []byte("POST"),
				URI:          []byte("/foo"),
				Host:         []byte("192.168.110.200:5555"),
			},
		},
		{
			"HTTP/1.1 200 OK\r\n",
			LazyHTTP{
				Decoded: true,
				Valid:   false,
			},
		},
		{
			"GET2 / HTTP/1.1\r\n",
			LazyHTTP{
				Decoded: true,
				Valid:   false,
			},
		},
		{
			"GET / HTTP/1.1\n",
			LazyHTTP{
				Decoded: true,
				Valid:   false,
			},
		},
		{
			"GET  \n",
			LazyHTTP{
				Decoded: true,
				Valid:   false,
			},
		},
	}

	for _, tc := range testCases {
		var lz LazyHTTP
		err := lz.DecodeFromData([]byte(tc.content))
		assert.Equal(t, tc.lazy.Valid, lz.Valid, tc.content)
		if err != nil {
			continue
		}

		assert.Equal(t, tc.lazy.VersionMajor, lz.VersionMajor, tc.content)
		assert.Equal(t, tc.lazy.VersionMinor, lz.VersionMinor, tc.content)
		assert.Equal(t, tc.lazy.Method, lz.Method, tc.content)
		assert.Equal(t, tc.lazy.URI, lz.URI, tc.content)
		assert.Equal(t, tc.lazy.Host, lz.Host, tc.content)
	}
}
