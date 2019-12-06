package main

import "encoding/base64"

func decodeBytes(enc []byte) ([]byte, error) {
	encoding := base64.RawURLEncoding
	dec := make([]byte, encoding.DecodedLen(len(enc)))
	if _, err := encoding.Decode(dec, enc); err != nil {
		return nil, err
	}
	return dec, nil
}

// reader := base64.NewDecoder(base64.RawURLEncoding, reader)

func encodeBytes(dec []byte) []byte {
	encoding := base64.RawURLEncoding
	enc := make([]byte, encoding.EncodedLen(len(dec)))
	encoding.Encode(enc, dec)
	return enc
}

// writer := base64.NewEncoder(base64.RawURLEncoding, writer)

// encoded := base64.RawURLEncoding.EncodeToString([]byte("hello"))
// decoded, err := base64.RawURLEncoding.DecodeString(encoded)
