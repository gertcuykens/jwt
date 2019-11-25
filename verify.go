package jwt

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strings"
)

func Verify25519(fn http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		cookie, err := r.Cookie("Authorization")
		if err != nil {
			jsonResponse(w, err.Error(), http.StatusUnauthorized)
			return
		}

		t := strings.Split(cookie.Value, ".")
		if len(t) < 3 {
			jsonResponse(w, "token invalid", http.StatusBadRequest)
			return
		}

		t1, err := base64.RawURLEncoding.DecodeString(t[1])
		if err != nil {
			jsonResponse(w, err.Error(), http.StatusBadRequest)
			return
		}

		var pl Authorization
		err = json.Unmarshal(t1, &pl)
		if err != nil {
			jsonResponse(w, err.Error(), http.StatusUnauthorized)
			return
		}

		t2, err := base64.RawURLEncoding.DecodeString(t[2])
		if err != nil {
			jsonResponse(w, err.Error(), http.StatusBadRequest)
			return
		}

		rp, err := http.NewRequest("GET", pl.Issuer, nil)
		if err != nil {
			jsonResponse(w, err.Error(), http.StatusBadRequest)
			return
		}

		var public ed25519.PublicKey
		err = get(rp, func(b []byte) { public = decodePublicKey(b) })
		if err != nil || public == nil {
			jsonResponse(w, "public nil: "+err.Error(), http.StatusBadRequest)
			return
		}

		valid := ed25519.Verify(public, []byte(t[0]+"."+t[1]), t2)
		if !valid {
			jsonResponse(w, "ed25519 invalid", http.StatusUnauthorized)
			return
		}

		ctx := r.Context()
		ctx = context.WithValue(ctx, Cookie("Authorization"), pl)
		r = r.WithContext(ctx)

		fn(w, r)
	}
}
