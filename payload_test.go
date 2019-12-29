package jwt

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
)

func ExamplePayload() {
	seed, err := base64.RawURLEncoding.DecodeString("9ZmhLw2OOCeTXHj02b6LI7Irl7Hw97msGd7o_jhiDkU")
	if err != nil {
		panic(err)
	}

	pk := ed25519.NewKeyFromSeed(seed)

	p1 := Payload{
		PrivateKey: pk,
		Subject:    "sub",
	}
	j, err := json.Marshal(p1)
	if err != nil {
		fmt.Println(err)
	}
	// fmt.Println(string(j))

	p2 := Payload{
		PublicKey: pk.Public().(ed25519.PublicKey),
		Validator: []Validator{ValidSubject("sub")},
	}
	err = json.Unmarshal(j, &p2)
	if err != nil {
		fmt.Println(err)
	}
	fmt.Printf("%s", p2.Subject)

	// Output:
	// sub
}
