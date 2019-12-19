package jwt

import (
	"encoding/base64"
	"encoding/json"
)

var encoding = base64.RawURLEncoding

func decodeBytes(enc []byte) ([]byte, error) {
	dec := make([]byte, encoding.DecodedLen(len(enc)))
	if _, err := encoding.Decode(dec, enc); err != nil {
		return nil, err
	}
	return dec, nil
}

func encodeBytes(dec []byte) []byte {
	enc := make([]byte, encoding.EncodedLen(len(dec)))
	encoding.Encode(enc, dec)
	return enc
}

func encodeSize(size int) int {
	return encoding.EncodedLen(size)
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
