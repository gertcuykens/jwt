package main

import (
	"crypto/ed25519"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/gertcuykens/jwt"
)

type myHandler func(w http.ResponseWriter, r *http.Request)

func (h *myHandler) GET(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=UTF-8")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("OK"))
}

func main() {

	var pk ed25519.PrivateKey = func() ed25519.PrivateKey {
		seed, err := base64.RawURLEncoding.DecodeString(os.Getenv("SEED"))
		if err != nil {
			panic(err)
		}
		return ed25519.NewKeyFromSeed(seed)
	}()

	var fn myHandler
	fn = func(w http.ResponseWriter, r *http.Request) {
		cookie, err := r.Cookie("Authorization")
		if err != nil {
			w.WriteHeader(http.StatusUnauthorized)
			w.Write([]byte(err.Error()))
			return
		}

		validator := []jwt.Validator{
			jwt.ValidIssuer(r.Referer()),
			jwt.ValidAudience([]string{"aud"}),
			jwt.ValidNotBefore(time.Now()),
			jwt.ValidIssuedAt(time.Now()),
			jwt.ValidExpirationTime(time.Now()),
		}

		auth := jwt.Payload{
			PublicKey: pk.Public().(ed25519.PublicKey),
			Validator: validator,
		}

		err = auth.UnmarshalJSON([]byte(fmt.Sprintf(`"%s"`, cookie.Value)))
		if err != nil {
			w.WriteHeader(http.StatusUnauthorized)
			w.Write([]byte(err.Error()))
			return
		}

		switch {
		case r.Method == http.MethodGet:
			fn.GET(w, r)
		default:
			w.WriteHeader(http.StatusMethodNotAllowed)
			w.Write([]byte("method not allowed"))
		}
	}

	x := http.NewServeMux()

	x.Handle("/", http.HandlerFunc(fn))

	x.HandleFunc("/public", func(w http.ResponseWriter, r *http.Request) {
		x509PublicKey, err := x509.MarshalPKIXPublicKey(pk.Public().(ed25519.PublicKey))
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte(err.Error()))
			return
		}
		w.Header().Set("Content-Type", "text/plain; charset=UTF-8")
		w.WriteHeader(http.StatusOK)
		w.Write(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: x509PublicKey}))
	})

	x.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		u, p, ok := r.BasicAuth()
		if !ok || p != "admin" {
			w.Header().Set("WWW-Authenticate", `Basic realm="`+r.Referer()+`"`)
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		pl := jwt.Payload{
			PrivateKey:     pk,
			Issuer:         r.Referer(),
			Audience:       []string{"aud"},
			ExpirationTime: jwt.NumericDate(time.Now().Add(1 * time.Hour)),
			Subject:        u,
		}
		v, err := json.Marshal(pl)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte(err.Error()))
			return
		}
		c := strings.Trim(string(v), `"`)
		http.SetCookie(w, &http.Cookie{Path: "/", Name: "Authorization", Value: c, HttpOnly: true, SameSite: http.SameSiteStrictMode})
		w.Header().Set("Location", "/")
		w.WriteHeader(http.StatusSeeOther)
	})

	x.HandleFunc("/logout", func(w http.ResponseWriter, r *http.Request) {
		http.SetCookie(w, &http.Cookie{Path: "/", Name: "Authorization", Value: "", HttpOnly: true, SameSite: http.SameSiteStrictMode, MaxAge: -1})
		// w.Header().Set("Clear-Site-Data", `"cookies"`)
		w.Header().Set("Content-Type", "text/plain; charset=UTF-8")
		w.Header().Set("Location", "/")
		w.WriteHeader(http.StatusSeeOther)
	})

	if err := http.ListenAndServe(":8080", x); err != nil {
		panic(err)
	}
}
