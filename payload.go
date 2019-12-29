package jwt

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
)

type Payload struct {
	PrivateKey     ed25519.PrivateKey `json:"-"`
	PublicKey      ed25519.PublicKey  `json:"-"`
	Validator      []Validator        `json:"-"`
	Issuer         string             `json:"iss,omitempty"`
	Subject        string             `json:"sub,omitempty"`
	Audience       Audience           `json:"aud,omitempty"`
	ExpirationTime *Time              `json:"exp,omitempty"`
	NotBefore      *Time              `json:"nbf,omitempty"`
	IssuedAt       *Time              `json:"iat,omitempty"`
	JWTID          string             `json:"jti,omitempty"`
}

func (p Payload) MarshalJSON() ([]byte, error) {
	type T Payload
	j, err := json.Marshal(struct{ T }{T: (T)(p)})
	if err != nil {
		return nil, err
	}

	enc := base64.RawURLEncoding
	p6l := enc.EncodedLen(len(j))
	s6l := enc.EncodedLen(ed25519.SignatureSize)

	t := make([]byte, 1+p6l+1+s6l+1)
	t[0] = '"'
	enc.Encode(t[1:], j)
	t[1+p6l] = '.'
	enc.Encode(t[1+p6l+1:], ed25519.Sign(p.PrivateKey, j)) // copy(t[1+p6l+1:], sig)
	t[len(t)-1] = '"'

	return t, nil
}

func (p *Payload) UnmarshalJSON(b []byte) error {
	i := bytes.IndexByte(b, '.')
	if i < 0 {
		return errors.New("no .")
	}

	encoding := base64.RawURLEncoding

	pl := make([]byte, encoding.DecodedLen(len(b[1:i])))
	_, err := encoding.Decode(pl, b[1:i])
	if err != nil {
		return err
	}

	sig := make([]byte, encoding.DecodedLen(len(b[i+1:len(b)-1])))
	_, err = encoding.Decode(sig, b[i+1:len(b)-1])
	if err != nil {
		return err
	}

	if !ed25519.Verify(p.PublicKey, pl, sig) {
		return errors.New("invalid signiture")
	}

	type T Payload
	t := struct{ *T }{T: (*T)(p)}
	if err := json.Unmarshal(pl, &t); err != nil {
		return err
	}

	for _, v := range p.Validator {
		if err = v(*p); err != nil {
			return err
		}
	}

	return nil
}
