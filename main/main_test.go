package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"

	jwt "github.com/gertcuykens/jwt"
)

func ExampleCookie() {
	s := jwt.NewServer(zero)

	r0 := httptest.NewRequest("GET", "/subject", nil)
	r0.AddCookie(&http.Cookie{Name: "Authorization", Value: "test", HttpOnly: true, SameSite: http.SameSiteStrictMode})
	w0 := httptest.NewRecorder()
	s.Subject(w0, r0)

	r1 := httptest.NewRequest("GET", "/sign/test-path", nil)
	r1.Header = http.Header{"Cookie": w0.HeaderMap["Set-Cookie"]}
	w1 := httptest.NewRecorder()
	s.Sign(w1, r1)

	fmt.Printf("%d - %s\n", w1.Code, w1.Body.String())

	r2 := httptest.NewRequest("GET", "/verify", nil)
	r2.Header = http.Header{"Cookie": w1.HeaderMap["Set-Cookie"]}
	w2 := httptest.NewRecorder()
	s.Verify(w2, r2)

	fmt.Printf("%d - %s\n", w2.Code, w2.Body.String())

	r3 := &http.Request{Header: http.Header{"Cookie": w2.HeaderMap["Set-Cookie"]}}
	c, err := r3.Cookie("Authorization")
	if err != nil {
		fmt.Printf("%+v\n", err)
		return
	}
	// fmt.Printf("%+v\n", c.Value)

	t := strings.Split(c.Value, ".")
	if len(t) < 2 {
		return
	}

	v, err := base64.RawURLEncoding.DecodeString(t[1])
	if err != nil {
		fmt.Println("decode error:", err)
		return
	}
	// fmt.Println(string(v))

	var pl jwt.ServerPayload
	err = json.Unmarshal(v, &pl)
	if err != nil {
		fmt.Println(err)
	}

	fmt.Printf("%+v\n", pl)

	// Output:
	// 1
}
