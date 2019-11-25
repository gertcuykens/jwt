package jwt

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"os"
)

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

func decodePublicKey(pemPublicKey []byte) ed25519.PublicKey {
	block, _ := pem.Decode(pemPublicKey)
	publicKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
		return nil
	}
	return publicKey.(ed25519.PublicKey)
}

func randS64() string {
	buf := make([]byte, 8)
	if n, err := io.ReadFull(rand.Reader, buf); err != nil {
		panic(err)
	} else if n != 8 {
		panic(err)
	}
	return base64.RawURLEncoding.EncodeToString(buf)
}

func randU64() uint64 {
	buf := make([]byte, 8)
	if n, err := io.ReadFull(rand.Reader, buf); err != nil {
		panic(err)
	} else if 8 != n {
		panic(err)
	}
	return binary.LittleEndian.Uint64(buf)
}

func get(r *http.Request, f func([]byte)) error {
	res, err := http.DefaultClient.Do(r)
	if err != nil {
		return err
	}
	b, err := ioutil.ReadAll(res.Body)
	res.Body.Close()
	if err != nil {
		return err
	}
	f(b)
	if c, ok := res.Header["Set-Cookie"]; ok {
		r.Header = http.Header{"Cookie": c}
	}
	return nil
}
