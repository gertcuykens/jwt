package jwt

import (
	"encoding/base64"
	"errors"
	"testing"

	"github.com/google/go-cmp/cmp"
)

func TestDecode(t *testing.T) {
	stdEnc := base64.StdEncoding
	rawURLEnc := base64.RawURLEncoding

	type decodeTest struct {
		X string `json:"x,omitempty"`
	}

	testCases := []struct {
		encoding *base64.Encoding
		json     string
		expected string
		errors   bool
	}{
		{rawURLEnc, "{}", "", false},
		{rawURLEnc, `{"x":"test"}`, "test", false},
		{stdEnc, "{}", "", true},
		{stdEnc, `{"x":"test"}`, "test", false},
		{nil, "{}", "", true},
		{nil, `{"x":"test"}`, "", true},
	}

	for _, tc := range testCases {
		t.Run(tc.json, func(t *testing.T) {
			b64 := tc.json
			if tc.encoding != nil {
				b64 = tc.encoding.EncodeToString([]byte(tc.json))
			}
			t.Logf("b64: %s", b64)

			var dt decodeTest
			err := unmarshal([]byte(b64), &dt)
			if want, got := tc.errors, errors.As(err, new(base64.CorruptInputError)); want != got {
				t.Errorf("want %t, got %t: %v", want, got, err)
			}
			if want, got := tc.expected, dt.X; want != got {
				t.Errorf("unmarshal (-want +got):\n%s", cmp.Diff(want, got))
			}
		})
	}

}
