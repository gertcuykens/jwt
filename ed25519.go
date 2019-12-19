package jwt

import (
	"crypto/ed25519"
	"errors"
)

var (
	ErrEd25519NilPrivKey   = errors.New("private key is nil")
	ErrEd25519NilPubKey    = errors.New("public key is nil")
	ErrEd25519Verification = errors.New("verification failed")
)

type PrivateKey ed25519.PrivateKey

func NewPrivateKey(seed []byte) PrivateKey {
	return PrivateKey(ed25519.NewKeyFromSeed(seed))
}

func (PrivateKey) Name() string {
	return "Ed25519"
}

func (pk PrivateKey) Sign(payload []byte) ([]byte, error) {
	if pk == nil {
		return nil, ErrEd25519NilPrivKey
	}
	return encodeBytes(ed25519.Sign(ed25519.PrivateKey(pk), payload)), nil
}

func (PrivateKey) Size() int {
	return encodeSize(ed25519.SignatureSize)
}

func (pk PrivateKey) Verify(payload, sig []byte) (err error) {
	if pk == nil {
		return ErrEd25519NilPubKey
	}
	if sig, err = decodeBytes(sig); err != nil {
		return err
	}
	pub := ed25519.PrivateKey(pk).Public().(ed25519.PublicKey)
	if !ed25519.Verify(pub, payload, sig) {
		return ErrEd25519Verification
	}
	return nil
}

func (pk PrivateKey) Public() ed25519.PublicKey {
	if pk != nil {
		return ed25519.PrivateKey(pk).Public().(ed25519.PublicKey)
	}
	return nil
}

func VerifyEd25519(pub ed25519.PublicKey, payload, sig []byte) (err error) {
	if sig, err = decodeBytes(sig); err != nil {
		return err
	}
	if !ed25519.Verify(pub, payload, sig) {
		return ErrEd25519Verification
	}
	return nil
}

type Algorithm interface {
	Name() string
	Sign(payload []byte) ([]byte, error)
	Size() int
	Verify(payload, sig []byte) error
}
