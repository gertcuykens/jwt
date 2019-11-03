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
	"strings"
	"time"

	"github.com/gbrlsnchs/jwt/v3"
)

type Server struct {
	hs jwt.Algorithm
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
				ed25519.PrivateKey(private)))}
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
	}

	now := time.Now()
	pl := jwt.Payload{
		Issuer:         r.Referer(),
		Subject:        obj.usr,
		Audience:       jwt.Audience{"http://localhost:8080", "https://jwt.io"},
		ExpirationTime: jwt.NumericDate(now.Add(time.Hour)),
		IssuedAt:       jwt.NumericDate(now),
		JWTID:          obj.pwd,
	}

	token, err := jwt.Sign(pl, s.hs)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Authorization", "Bearer "+string(token))
	fmt.Fprintf(w, `{"Authorization": "Bearer %s"}`, string(token))
	fmt.Printf("Bearer %s\n", token)
}

func (s Server) Verify(w http.ResponseWriter, r *http.Request) {
	token := r.Header.Get("Authorization")
	token = strings.TrimPrefix(token, "Bearer ")
	var pl jwt.Payload
	_, err := jwt.Verify([]byte(token), s.hs, &pl)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
	}
	fmt.Printf("%+v\n", pl)
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Authorization", "Bearer "+string(token))
	fmt.Fprintf(w, `{"Authorization": "Bearer %s"}`, string(token))
	fmt.Printf("Bearer %s\n", token)
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
