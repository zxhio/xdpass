package profile

import (
	"net"
	"net/http"
	"net/http/pprof"
)

func Serve(lis net.Listener) error {
	mux := http.NewServeMux()

	mux.HandleFunc("/xdpass-pprof/", pprof.Index)
	mux.HandleFunc("/xdpass-pprof/cmdline", pprof.Cmdline)
	mux.HandleFunc("/xdpass-pprof/profile", pprof.Profile)
	mux.HandleFunc("/xdpass-pprof/symbol", pprof.Symbol)
	mux.HandleFunc("/xdpass-pprof/trace", pprof.Trace)

	mux.Handle("/xdpass-pprof/goroutine", pprof.Handler("goroutine"))
	mux.Handle("/xdpass-pprof/heap", pprof.Handler("heap"))
	mux.Handle("/xdpass-pprof/threadcreate", pprof.Handler("threadcreate"))
	mux.Handle("/xdpass-pprof/block", pprof.Handler("block"))
	mux.Handle("/xdpass-pprof/mutex", pprof.Handler("mutex"))

	return http.Serve(lis, mux)
}
