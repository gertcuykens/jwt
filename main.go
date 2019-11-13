package main

import (
	"crypto/ed25519"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/gbrlsnchs/jwt/v3"
)

type ServerPayload struct {
	jwt.Payload
	Method string `json:"method, omitempty"`
}

type Server struct {
	c jwt.Algorithm
}

func NewServer() Server {
	public, private, err := ed25519.GenerateKey(zero)
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
	obj := struct {
		Name   string
		Method string
		Path   string
	}{}
	err := json.NewDecoder(r.Body).Decode(&obj)
	if err != nil {
		jsonResponse(w, err, 500)
		return
	}

	now := time.Now()
	pl := ServerPayload{
		Payload: jwt.Payload{
			Issuer:         r.Referer(),
			Subject:        obj.Path,
			Audience:       jwt.Audience{os.Getenv("ORIGIN")},
			ExpirationTime: jwt.NumericDate(now.Add(time.Hour)),
			IssuedAt:       jwt.NumericDate(now),
			JWTID:          obj.Name,
		},
		Method: obj.Method,
	}

	token, err := jwt.Sign(pl, s.c)
	if err != nil {
		jsonResponse(w, err, 500)
		return
	}

	http.SetCookie(w, &http.Cookie{Name: "Authorization", Value: string(token)})
	jsonResponse(w, string(token), 200)
	// TODO: Send to Authorization server
}

func (s Server) Verify(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie("Authorization")

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
		jsonResponse(w, err, 500)
		return
	}

	pl.ExpirationTime = jwt.NumericDate(now.Add(time.Hour))
	token, err := jwt.Sign(pl, s.c)
	if err != nil {
		jsonResponse(w, err, 500)
		return
	}
	// fmt.Printf("%+v\n", pl)

	http.SetCookie(w, &http.Cookie{Name: "Authorization", Value: string(token), HttpOnly: true, SameSite: http.SameSiteStrictMode})
	jsonResponse(w, string(token), 200)
	// TODO: Verify Authorization server
}

func encodePublicKey(publicKey ed25519.PublicKey) []byte {
	x509PublicKey, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		panic(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: x509PublicKey})
}

func main() {
	fmt.Println(os.Getenv("ORIGIN"))
	s := NewServer()
	http.Handle("/", http.FileServer(http.Dir("pub")))
	http.HandleFunc("/sign", s.Sign)
	http.HandleFunc("/verify", s.Verify)
	log.Fatal(http.ListenAndServe(":8081", nil))
}

func jsonResponse(w http.ResponseWriter, v interface{}, c int) {
	if c != http.StatusOK {
		fmt.Fprintf(os.Stderr, "%d - %+v\n", c, v)
	}
	j, err := json.MarshalIndent(v, "", "\t")
	if err != nil {
		fmt.Fprintln(os.Stderr, "500 - ", err)
		w.Header().Set("Content-Type", "text/plain; charset=UTF-8")
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(c)
	w.Write(j)
}
