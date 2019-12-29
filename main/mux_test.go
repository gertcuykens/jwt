package main

import (
	"crypto/ed25519"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"

	"github.com/gertcuykens/jwt"
)

func ExampleServeMux() {
	iss := os.Getenv("ORIGIN") + "/public"
	aud := []string{os.Getenv("ORIGIN") + "/verify"}
	seed, err := base64.RawURLEncoding.DecodeString(os.Getenv("SEED"))
	if err != nil {
		panic(err)
	}
	pk := ed25519.NewKeyFromSeed(seed)

	x := NewServeMux(iss, aud, pk)
	ts := httptest.NewServer(x)
	defer ts.Close()

	r, _ := http.NewRequest("GET", ts.URL+"/authorization", nil)
	r.AddCookie(&http.Cookie{Name: "Authorization", Value: "OK", HttpOnly: true, SameSite: http.SameSiteNoneMode})
	get(r, func(b []byte) {})

	r.URL, _ = url.Parse(ts.URL + "/sign")
	get(r, func(b []byte) {})

	cookie, err := r.Cookie("Authorization")
	if err != nil {
		panic(err)
	}

	var public ed25519.PublicKey
	r.URL, _ = url.Parse(ts.URL + "/public")
	get(r, func(b []byte) { public = decodePublicKey(b) })

	pl := jwt.Payload{
		// PublicKey: pk.Public().(ed25519.PublicKey),
		PublicKey: public,
	}

	err = json.Unmarshal([]byte(fmt.Sprintf(`"%s"`, cookie.Value)), &pl)
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println(pl.Subject)

	// Output:
	// OK
}

func get(r *http.Request, f func([]byte)) error {
	res, err := http.DefaultClient.Do(r)
	if err != nil {
		return err
	}
	b, err := ioutil.ReadAll(res.Body)
	res.Body.Close()
	if err != nil {
		return err
	}
	f(b)
	if c, ok := res.Header["Set-Cookie"]; ok {
		r.Header = http.Header{"Cookie": c}
	}
	return nil
}

func decodePublicKey(pemPublicKey []byte) ed25519.PublicKey {
	block, _ := pem.Decode(pemPublicKey)
	publicKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
		return nil
	}
	return publicKey.(ed25519.PublicKey)
}
