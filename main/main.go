package main

import (
	"fmt"
	"net/http"
	"net/url"
	"os"
)

func main() {
	origin, err := url.Parse(os.Getenv("ORIGIN"))
	if err != nil {
		panic(err)
	}

	p := origin.Port()
	if os.Getenv("PORT") != "" {
		p = os.Getenv("PORT")
	}

	mux := NewServeMux(os.Getenv("ORIGIN")+"/public", []string{os.Getenv("ORIGIN") + "/verify"}, nil)
	mux.HandleFunc("/origin", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, "%q", os.Getenv("ORIGIN"))
	})
	mux.Handle("/", http.FileServer(http.Dir("./pub")))
	if err := http.ListenAndServe(":"+p, corsHandler(mux)); err != nil {
		fmt.Fprintln(os.Stderr, err)
	}
}
