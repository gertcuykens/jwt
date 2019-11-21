package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"strings"

	"github.com/gertcuykens/jwt"
)

func ExampleServeMux() {
	x := jwt.NewServeMux(zero)
	ts := httptest.NewServer(x)
	defer ts.Close()

	r, _ := http.NewRequest("GET", ts.URL+"/authorization", nil)
	r.AddCookie(&http.Cookie{Name: "Authorization", Value: "test", HttpOnly: true, SameSite: http.SameSiteNoneMode})
	c := get(r, func(b []byte) {})

	r, _ = http.NewRequest("GET", ts.URL+"/sign", nil)
	r.Header = http.Header{"Cookie": c}
	c = get(r, func(b []byte) {})

	r, _ = http.NewRequest("GET", ts.URL+"/verify", nil)
	r.Header = http.Header{"Cookie": c}
	get(r, func(b []byte) {})

	r = &http.Request{}
	r.Header = http.Header{"Cookie": c}
	cookie, _ := r.Cookie("Authorization")

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
	r, _ = http.NewRequest("GET", ts.URL+"/public", nil)
	get(r, func(b []byte) {
		public = decodePublicKey(b)
	})

	valid := ed25519.Verify(public, t0, t2)
	fmt.Println("verified:", valid)

	// Output:
	// test
	// verified: true
}

func get(r *http.Request, f func([]byte)) []string {
	res, err := http.DefaultClient.Do(r)
	if err != nil {
		panic(err)
	}
	b, err := ioutil.ReadAll(res.Body)
	res.Body.Close()
	if err != nil {
		panic(err)
	}
	f(b)

	return res.Header["Set-Cookie"]
}
