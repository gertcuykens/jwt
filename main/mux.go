package main

import (
	"io"
	"net/http"

	"github.com/gertcuykens/jwt"
)

func NewServeMux(iss string, aud []string, r io.Reader) *http.ServeMux {
	c := NewEd25519()

	x := http.NewServeMux()

	x.HandleFunc("/public", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=UTF-8")
		w.Write(encodePublicKey(c.Public()))
	})

	x.HandleFunc("/sign", jwt.Sign(iss, aud, c, func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		if v := ctx.Value(jwt.Cookie("Error")); v != nil {
			jsonResponse(w, v.(error).Error(), http.StatusBadRequest)
			return
		}
		if v := ctx.Value(jwt.Cookie("Authorization")); v != nil {
			http.SetCookie(w, &http.Cookie{Path: "/", Name: "Authorization", Value: v.(string), HttpOnly: true, SameSite: http.SameSiteNoneMode})
			jsonResponse(w, v.(string), http.StatusOK)
			return
		}
		jsonResponse(w, "authorization not found in context", http.StatusUnauthorized)
	}))

	x.HandleFunc("/verify", jwt.Verify(iss, aud, c, func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		if v := ctx.Value(jwt.Cookie("Error")); v != nil {
			jsonResponse(w, v.(error).Error(), http.StatusBadRequest)
			return
		}
		if v := ctx.Value(jwt.Cookie("Authorization")); v != nil {
			pl := v.(jwt.Authorization)
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
			pl := v.(jwt.Authorization)
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
