package main

import (
	"crypto/ed25519"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"log"
	"math/rand"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/gbrlsnchs/jwt/v3"
)

type Server struct {
	c jwt.Algorithm
	n *rand.Rand
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
		rand.New(rand.NewSource(0)),
	}
}

func (s Server) Sign(w http.ResponseWriter, r *http.Request) {
	obj := struct {
		usr string
		pwd string
	}{}
	var c = json.NewDecoder(r.Body)
	err := c.Decode(&obj)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return
	}

	// TODO: (usr, pwd)

	now := time.Now()
	pl := jwt.Payload{
		Issuer:         r.Referer(),
		Subject:        obj.usr,
		Audience:       jwt.Audience{"http://localhost:8080"},
		ExpirationTime: jwt.NumericDate(now.Add(time.Hour)),
		IssuedAt:       jwt.NumericDate(now),
		JWTID:          string(s.n.Intn(100)),
	}

	token, err := jwt.Sign(pl, s.c)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return
	}

	fmt.Printf("%+v\n", pl)

	http.SetCookie(w, &http.Cookie{Name: "Authorization", Value: string(token)})
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Authorization", "Bearer "+string(token))
	fmt.Fprintf(w, `{"Authorization": "Bearer %s"}`, string(token))
	// fmt.Printf("Bearer %s\n", string(token))
}

func (s Server) Verify(w http.ResponseWriter, r *http.Request) {
	token := r.Header.Get("Authorization")
	token = strings.TrimPrefix(token, "Bearer ")

	var (
		pl           jwt.Payload
		now          = time.Now()
		hdValidator  = jwt.ValidateHeader
		iatValidator = jwt.IssuedAtValidator(now)
		expValidator = jwt.ExpirationTimeValidator(now)
		audValidator = jwt.AudienceValidator(jwt.Audience{"http://localhost:8080"})
		plValidator  = jwt.ValidatePayload(&pl, iatValidator, expValidator, audValidator)
	)

	_, err := jwt.Verify([]byte(token), s.c, &pl, hdValidator, plValidator)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s %+v", err, pl)
		return
	}

	pl.ExpirationTime = jwt.NumericDate(now.Add(time.Hour))
	refresh, err := jwt.Sign(pl, s.c)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return
	}

	fmt.Printf("%+v\n", pl)

	http.SetCookie(w, &http.Cookie{Name: "Authorization", Value: string(refresh)})
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Authorization", "Bearer "+string(refresh))
	fmt.Fprintf(w, `{"Authorization": "Bearer %s"}`, string(refresh))
	// fmt.Printf("Bearer %s\n", string(refresh))
}

func encodePublicKey(publicKey ed25519.PublicKey) []byte {
	x509PublicKey, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		panic(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: x509PublicKey})
}

func main() {
	s := NewServer()
	http.Handle("/", http.FileServer(http.Dir("pub")))
	http.HandleFunc("/sign", s.Sign)
	http.HandleFunc("/verify", s.Verify)
	log.Fatal(http.ListenAndServe(":8080", nil))
}
