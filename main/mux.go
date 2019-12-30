package main

import (
	"crypto/ed25519"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/gertcuykens/jwt"
)

func NewServeMux(iss string, aud []string, pk ed25519.PrivateKey) *http.ServeMux {
	x := http.NewServeMux()

	x.HandleFunc("/public", func(w http.ResponseWriter, r *http.Request) {
		x509PublicKey, err := x509.MarshalPKIXPublicKey(pk.Public().(ed25519.PublicKey))
		if err != nil {
			jsonResponse(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "text/plain; charset=UTF-8")
		w.Write(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: x509PublicKey}))
	})

	x.HandleFunc("/sign", func(w http.ResponseWriter, r *http.Request) {
		cookie, err := r.Cookie("Authorization")
		if err != nil {
			jsonResponse(w, err.Error(), http.StatusUnauthorized)
			return
		}
		pl := jwt.Payload{
			PrivateKey:     pk,
			Issuer:         iss,
			Audience:       aud,
			ExpirationTime: jwt.NumericDate(time.Now().Add(1 * time.Hour)),
			Subject:        cookie.Value,
		}
		v, err := json.Marshal(pl)
		if err != nil {
			jsonResponse(w, err.Error(), http.StatusBadRequest)
			return
		}
		c := strings.Trim(string(v), `"`)
		http.SetCookie(w, &http.Cookie{Path: "/", Name: "Authorization", Value: c, HttpOnly: true, SameSite: http.SameSiteNoneMode})
		jsonResponse(w, c, http.StatusOK)
	})

	x.HandleFunc("/verify", func(w http.ResponseWriter, r *http.Request) {
		cookie, err := r.Cookie("Authorization")
		if err != nil {
			jsonResponse(w, err.Error(), http.StatusUnauthorized)
			return
		}

		pl := jwt.Payload{
			PublicKey: pk.Public().(ed25519.PublicKey),
			Validator: []jwt.Validator{
				jwt.ValidIssuer(iss),
				jwt.ValidAudience(jwt.Audience(aud)),
				jwt.ValidNotBefore(time.Now()),
				jwt.ValidIssuedAt(time.Now()),
				jwt.ValidExpirationTime(time.Now()),
			},
		}

		v := fmt.Sprintf(`"%s"`, cookie.Value)

		err = pl.UnmarshalJSON([]byte(v))
		if err != nil {
			jsonResponse(w, err.Error(), http.StatusUnauthorized)
			return
		}

		jsonResponse(w, cookie.Value, http.StatusOK)
	})

	x.HandleFunc("/authorization", func(w http.ResponseWriter, r *http.Request) {
		cookie, err := r.Cookie("Authorization")
		if err != nil {
			jsonResponse(w, err.Error(), http.StatusUnauthorized)
			return
		}
		http.SetCookie(w, &http.Cookie{Path: "/", Name: "Authorization", Value: cookie.Value, HttpOnly: true, SameSite: http.SameSiteNoneMode})
		jsonResponse(w, cookie.Value, http.StatusOK)
	})

	x.HandleFunc("/logout", func(w http.ResponseWriter, r *http.Request) {
		http.SetCookie(w, &http.Cookie{Path: "/", Name: "Authorization", Value: "", HttpOnly: true, SameSite: http.SameSiteNoneMode, MaxAge: -1})
		jsonResponse(w, nil, http.StatusOK)
	})

	return x
}

func jsonResponse(w http.ResponseWriter, v interface{}, c int) {
	if c != http.StatusOK {
		fmt.Fprintf(os.Stderr, "%d - %+v\n", c, v)
	}
	w.Header().Set("Content-Type", "application/json")
	j, err := json.MarshalIndent(v, "", "\t")
	if err != nil {
		fmt.Fprintln(os.Stderr, http.StatusInternalServerError, " - ", err)
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprintf(w, "%q", err)
		return
	}
	w.WriteHeader(c)
	w.Write(j)
}
