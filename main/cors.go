package main

import "net/http"

func corsHandler(h http.Handler) http.Handler {
	return http.HandlerFunc(corsHandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			h.ServeHTTP(w, r)
		}))
}

func corsHandlerFunc(fn http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", r.Header.Get("Origin"))
		w.Header().Set("Access-Control-Allow-Headers", "content-type, authorization")
		w.Header().Set("Access-Control-Allow-Methods", "GET, PUT, POST, DELETE, PATCH, HEAD, OPTIONS, TRACE, CONNECT")
		w.Header().Set("Access-Control-Allow-Credentials", "true")
		switch r.Method {
		case "OPTIONS":
		default:
			fn(w, r)
		}
	}
}
