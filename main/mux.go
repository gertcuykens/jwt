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

	"github.com/gertcuykens/jwt"
)

func NewServeMux() *http.ServeMux {
	iss := os.Getenv("ORIGIN") + "/public"
	aud := []string{os.Getenv("ORIGIN") + "/verify"}
	c := func() jwt.PrivateKey {
		b, err := base64.RawURLEncoding.DecodeString(os.Getenv("SEED"))
		if err != nil {
			panic(err)
		}
		return jwt.NewPrivateKey(b)
	}()

	x := http.NewServeMux()

	x.HandleFunc("/public", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=UTF-8")
		w.Write(encodePublicKey(c.Public()))
	})

	x.HandleFunc("/sign", func(w http.ResponseWriter, r *http.Request) {
		cookie, err := r.Cookie("Authorization")
		if err != nil {
			jsonResponse(w, err.Error(), http.StatusUnauthorized)
			return
		}
		v, err := jwt.SignCookie(c, cookie.Value, iss, aud)
		if err != nil {
			jsonResponse(w, err.Error(), http.StatusBadRequest)
			return
		}
		http.SetCookie(w, &http.Cookie{Path: "/", Name: "Authorization", Value: string(v), HttpOnly: true, SameSite: http.SameSiteNoneMode})
		jsonResponse(w, string(v), http.StatusOK)
	})

	x.HandleFunc("/verify", jwt.VerifyCookie(iss, aud, c, func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		if v := ctx.Value(jwt.Cookie("Error")); v != nil {
			jsonResponse(w, v.(error).Error(), http.StatusBadRequest)
			return
		}
		if v := ctx.Value(jwt.Cookie("Authorization")); v != nil {
			pl := v.(jwt.Payload)
			jsonResponse(w, pl, http.StatusOK)
			return
		}
		jsonResponse(w, "authorization not found in context", http.StatusUnauthorized)
	}))

	x.HandleFunc("/25519", jwt.Verify25519(iss, func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		if v := ctx.Value(jwt.Cookie("Error")); v != nil {
			jsonResponse(w, v.(error).Error(), http.StatusBadRequest)
			return
		}
		if v := ctx.Value(jwt.Cookie("Authorization")); v != nil {
			pl := v.(jwt.Payload)
			jsonResponse(w, pl, http.StatusOK)
			return
		}
		jsonResponse(w, "authorization not found in context", http.StatusUnauthorized)
	}))

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
		cookie, err := r.Cookie("Authorization")
		if err != nil {
			jsonResponse(w, err.Error(), http.StatusOK)
			return
		}
		jsonResponse(w, cookie.Value, http.StatusOK)
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

func encodePublicKey(publicKey ed25519.PublicKey) []byte {
	x509PublicKey, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
		return nil
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: x509PublicKey})
}
