package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"fmt"
	"net/http"
	"os"
)

func main() {
	p := "8080"
	if "" != os.Getenv("PORT") {
		p = os.Getenv("PORT")
	}

	iss := os.Getenv("ORIGIN") + "/public"
	aud := []string{os.Getenv("ORIGIN") + "/verify"}
	seed, err := base64.RawURLEncoding.DecodeString(os.Getenv("SEED"))
	if err != nil {
		panic(err)
	}
	pk := ed25519.NewKeyFromSeed(seed)

	mux := NewServeMux(iss, aud, pk)
	mux.Handle("/", http.FileServer(http.Dir("./pub")))
	if err := http.ListenAndServe(":"+p, mux); err != nil {
		fmt.Fprintln(os.Stderr, err)
	}
}
