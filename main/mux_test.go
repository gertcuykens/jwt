package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"

	"github.com/gertcuykens/jwt"
)

func ExampleServeMux() {
	x := NewServeMux("http://localhost:8080", zero)
	ts := httptest.NewServer(x)
	defer ts.Close()

	r, _ := http.NewRequest("GET", ts.URL+"/authorization", nil)
	r.AddCookie(&http.Cookie{Name: "Authorization", Value: "test", HttpOnly: true, SameSite: http.SameSiteNoneMode})
	get(r, func(b []byte) {})

	r.URL, _ = url.Parse(ts.URL + "/sign")
	get(r, func(b []byte) {})

	r.URL, _ = url.Parse(ts.URL + "/verify")
	get(r, func(b []byte) {})
	cookie, _ := r.Cookie("Authorization")

	// r.URL, _ = url.Parse(ts.URL + "/25519")
	// get(r, func(b []byte) { fmt.Println(string(b)) })

	t := strings.Split(cookie.Value, ".")
	if len(t) < 3 {
		return
	}
	t0 := []byte(t[0] + "." + t[1])

	t1, _ := base64.RawURLEncoding.DecodeString(t[1])

	var pl jwt.Authorization
	err := json.Unmarshal(t1, &pl)
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println(pl.Subject)

	t2, _ := base64.RawURLEncoding.DecodeString(t[2])

	var public ed25519.PublicKey
	r.URL, _ = url.Parse(ts.URL + "/public")
	get(r, func(b []byte) { public = decodePublicKey(b) })

	valid := ed25519.Verify(public, t0, t2)
	fmt.Println("verified:", valid)

	// Output:
	// test
	// verified: true
}
