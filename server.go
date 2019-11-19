package jwt

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"html"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/gbrlsnchs/jwt/v3"
)

type ServerPayload struct {
	jwt.Payload
	Method string `json:"method, omitempty"`
	Path   string `json:"path, omitempty"`
}

type Server struct {
	c jwt.Algorithm
}

func NewServer(r io.Reader) Server {
	public, private, err := ed25519.GenerateKey(r)
	if err != nil {
		panic(err)
	}
	fmt.Print(string(encodePublicKey(ed25519.PublicKey(public))))
	return Server{
		jwt.NewEd25519(
			jwt.Ed25519PrivateKey(
				ed25519.PrivateKey(private))),
	}
}

func (s Server) Sign(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie("Authorization")
	if err != nil {
		jsonResponse(w, err.Error(), http.StatusUnauthorized)
		return
	}

	now := time.Now()
	pl := ServerPayload{
		Payload: jwt.Payload{
			Issuer:         r.Referer(),
			Subject:        cookie.Value,
			Audience:       jwt.Audience{os.Getenv("ORIGIN")},
			ExpirationTime: jwt.NumericDate(now.Add(time.Hour)),
			IssuedAt:       jwt.NumericDate(now),
			JWTID:          rand64(),
		},
		Method: r.Method,
		// Method: r.Header.Get("Method"),
		Path: strings.TrimPrefix(html.UnescapeString(r.URL.Path), "/sign"),
	}

	token, err := jwt.Sign(pl, s.c)
	if err != nil {
		jsonResponse(w, err.Error(), 500)
		return
	}

	err = tokenDB.Put(id(pl.JWTID).ptr(), id(pl.Subject).ptr())
	if err != nil {
		jsonResponse(w, err.Error(), 500)
		return
	}

	http.SetCookie(w, &http.Cookie{Path: "/", Name: "Authorization", Value: string(token), HttpOnly: true, SameSite: http.SameSiteStrictMode})
	jsonResponse(w, pl, 200)
}

func (s Server) Verify(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie("Authorization")
	if err != nil {
		jsonResponse(w, err.Error(), http.StatusUnauthorized)
		return
	}

	var (
		pl           ServerPayload
		now          = time.Now()
		hdValidator  = jwt.ValidateHeader
		iatValidator = jwt.IssuedAtValidator(now)
		expValidator = jwt.ExpirationTimeValidator(now)
		audValidator = jwt.AudienceValidator(jwt.Audience{os.Getenv("ORIGIN")})
		plValidator  = jwt.ValidatePayload(&pl.Payload, iatValidator, expValidator, audValidator)
	)

	_, err = jwt.Verify([]byte(cookie.Value), s.c, &pl, hdValidator, plValidator)
	if err != nil {
		jsonResponse(w, err.Error(), 500)
		return
	}

	if !tokenDB.Listed(pl.JWTID) {
		jsonResponse(w, "not listed: "+pl.Subject, http.StatusUnauthorized)
		return
	}

	pl.ExpirationTime = jwt.NumericDate(now.Add(time.Hour))
	token, err := jwt.Sign(pl, s.c)
	if err != nil {
		jsonResponse(w, err.Error(), 500)
		err = tokenDB.Delete(id(cookie.Value).ptr())
		if err != nil {
			jsonResponse(w, err.Error(), http.StatusUnauthorized)
			return
		}
		return
	}

	http.SetCookie(w, &http.Cookie{Path: "/", Name: "Authorization", Value: string(token), HttpOnly: true, SameSite: http.SameSiteStrictMode})
	jsonResponse(w, pl, 200)
}

func (s Server) Subject(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie("Authorization")
	if err != nil {
		jsonResponse(w, err.Error(), http.StatusUnauthorized)
		return
	}
	http.SetCookie(w, &http.Cookie{Path: "/", Name: "Authorization", Value: cookie.Value, HttpOnly: true, SameSite: http.SameSiteStrictMode})
	jsonResponse(w, cookie.Value, 200)
}

func (s Server) Delete(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{Path: "/", Name: "Authorization", Value: "", HttpOnly: true, SameSite: http.SameSiteStrictMode, MaxAge: -1})
	cookie, err := r.Cookie("Authorization")
	if err != nil {
		jsonResponse(w, err.Error(), http.StatusUnauthorized)
		return
	}

	var (
		pl           ServerPayload
		hdValidator  = jwt.ValidateHeader
		audValidator = jwt.AudienceValidator(jwt.Audience{os.Getenv("ORIGIN")})
		plValidator  = jwt.ValidatePayload(&pl.Payload, audValidator)
	)

	_, err = jwt.Verify([]byte(cookie.Value), s.c, &pl, hdValidator, plValidator)
	if err != nil {
		jsonResponse(w, err.Error(), 500)
		return
	}

	err = tokenDB.Delete(id(pl.JWTID).ptr())
	if err != nil {
		jsonResponse(w, err.Error(), http.StatusUnauthorized)
		return
	}
	jsonResponse(w, pl, 200)
}

func encodePublicKey(publicKey ed25519.PublicKey) []byte {
	x509PublicKey, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		panic(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: x509PublicKey})
}

func jsonResponse(w http.ResponseWriter, v interface{}, c int) {
	if c != http.StatusOK {
		fmt.Fprintf(os.Stderr, "%d - %+v\n", c, v)
	}
	w.Header().Set("Content-Type", "application/json")
	j, err := json.MarshalIndent(v, "", "\t")
	if err != nil {
		fmt.Fprintln(os.Stderr, "500 - ", err)
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprintf(w, "%q", err)
		return
	}
	w.WriteHeader(c)
	w.Write(j)
}

func rand64() string {
	var buf [16]byte
	if n, err := io.ReadFull(rand.Reader, buf[:]); err != nil {
		panic(err)
	} else if n != 16 {
		panic(err)
	}
	return base64.RawURLEncoding.EncodeToString(buf[:])
}
