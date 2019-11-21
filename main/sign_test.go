package main

import (
	"crypto/ed25519"
	"crypto/x509"
	"encoding/pem"
	"fmt"
)

func Example25519() {
	public, private, err := ed25519.GenerateKey(zero)
	if err != nil {
		panic(err)
	}

	p := encodePublicKey(ed25519.PublicKey(public))
	public = decodePublicKey(p)

	s := ed25519.Sign(private, []byte("hello"))
	fmt.Printf("[% x]\n", s)

	v := ed25519.Verify(public, []byte("hello"), s)
	fmt.Println("valid:", v)
	// Output:
	// [e2 5c 87 23 d0 39 fe 8f 45 d6 c9 d6 a8 91 7f a9 1b c7 54 91 3c d5 96 fd 35 8a 49 3a 21 a3 cb 59 0a 65 37 ba bc 7d f0 40 0a b6 1a 05 58 9c 9c 36 b6 5a 14 38 78 cb 03 41 d4 e9 e4 84 19 c4 37 0d]
	// valid: true
}

func encodePublicKey(publicKey ed25519.PublicKey) []byte {
	x509PublicKey, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		panic(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: x509PublicKey})
}

func decodePublicKey(pemPublicKey []byte) ed25519.PublicKey {
	block, _ := pem.Decode(pemPublicKey)
	publicKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		panic(err)
	}
	return publicKey.(ed25519.PublicKey)
}
