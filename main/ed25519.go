package main

import (
	"crypto/ed25519"
	"errors"
)

var (
	ErrEd25519NilPrivKey   = errors.New("private key is nil")
	ErrEd25519NilPubKey    = errors.New("public key is nil")
	ErrEd25519Verification = errors.New("verification failed")
)

type Ed25519 ed25519.PrivateKey

func NewEd25519() Ed25519 {
	_, private, err := ed25519.GenerateKey(zero)
	if err != nil {
		panic(err)
	}
	return Ed25519(private)
}

func (Ed25519) Name() string {
	return "Ed25519"
}

func (ed Ed25519) Sign(payload []byte) ([]byte, error) {
	if ed == nil {
		return nil, ErrEd25519NilPrivKey
	}
	return ed25519.Sign(ed25519.PrivateKey(ed), payload), nil
}

func (Ed25519) Size() int {
	return ed25519.SignatureSize
}

func (ed Ed25519) Verify(payload, sig []byte) (err error) {
	if ed == nil {
		return ErrEd25519NilPubKey
	}
	if sig, err = decodeBytes(sig); err != nil {
		return err
	}
	pub := ed25519.PrivateKey(ed).Public().(ed25519.PublicKey)
	if !ed25519.Verify(pub, payload, sig) {
		return ErrEd25519Verification
	}
	return nil
}

func (ed Ed25519) Public() ed25519.PublicKey {
	if ed != nil {
		return ed25519.PrivateKey(ed).Public().(ed25519.PublicKey)
	}
	return nil
}
