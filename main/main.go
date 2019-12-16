package main

import (
	"fmt"
	"net/http"
	"os"
)

func main() {
	p := "8080"
	if "" != os.Getenv("PORT") {
		p = os.Getenv("PORT")
	}

	mux := NewServeMux()
	mux.Handle("/", http.FileServer(http.Dir("./pub")))
	if err := http.ListenAndServe(":"+p, mux); err != nil {
		fmt.Fprintln(os.Stderr, err)
	}
}
