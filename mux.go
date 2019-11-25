package jwt

import (
	"crypto/ed25519"
	"io"
	"net/http"

	"github.com/gbrlsnchs/jwt/v3"
)

func NewServeMux(iss string, r io.Reader) *http.ServeMux {
	public, private, err := ed25519.GenerateKey(r)
	if err != nil {
		panic(err)
	}

	c := jwt.NewEd25519(
		jwt.Ed25519PrivateKey(
			ed25519.PrivateKey(private)))

	x := http.NewServeMux()

	x.HandleFunc("/public", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=UTF-8")
		w.Write(encodePublicKey(ed25519.PublicKey(public)))
	})

	x.HandleFunc("/sign", Sign(iss, c, func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		v := ctx.Value(Cookie("Authorization"))
		if v == nil {
			jsonResponse(w, "authorization not found in context", http.StatusUnauthorized)
			return
		}
		http.SetCookie(w, &http.Cookie{Path: "/", Name: "Authorization", Value: v.(string), HttpOnly: true, SameSite: http.SameSiteNoneMode})
		jsonResponse(w, v.(string), http.StatusOK)
	}))

	x.HandleFunc("/verify", Verify(iss, c, func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		v := ctx.Value(Cookie("Error"))
		if v == nil {
			jsonResponse(w, nil, http.StatusOK)
			return
		}
		jsonResponse(w, v.(error).Error(), http.StatusUnauthorized)
	}))

	x.HandleFunc("/25519", Verify25519(func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		v := ctx.Value(Cookie("Authorization"))
		if v == nil {
			jsonResponse(w, "authorization not found in context", http.StatusUnauthorized)
			return
		}
		pl := v.(Authorization)
		jsonResponse(w, pl, http.StatusOK)
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
