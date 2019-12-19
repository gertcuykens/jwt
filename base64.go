package jwt

import (
	"encoding/base64"
	"encoding/json"
)

func decodeBytes(enc []byte) ([]byte, error) {
	encoding := base64.RawURLEncoding
	dec := make([]byte, encoding.DecodedLen(len(enc)))
	if _, err := encoding.Decode(dec, enc); err != nil {
		return nil, err
	}
	return dec, nil
}

func encodeBytes(dec []byte) []byte {
	encoding := base64.RawURLEncoding
	enc := make([]byte, encoding.EncodedLen(len(dec)))
	encoding.Encode(enc, dec)
	return enc
}

func marshal(v interface{}) ([]byte, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	enc := encodeBytes(b)
	if err != nil {
		return nil, err
	}
	return enc, nil
}

func unmarshal(enc []byte, v interface{}) error {
	dec, err := decodeBytes(enc)
	if err != nil {
		return err
	}
	return json.Unmarshal(dec, v)
}

// reader := base64.NewDecoder(base64.RawURLEncoding, reader)
// writer := base64.NewEncoder(base64.RawURLEncoding, writer)

// encoded := base64.RawURLEncoding.EncodeToString([]byte("hello"))
// decoded, err := base64.RawURLEncoding.DecodeString(encoded)
