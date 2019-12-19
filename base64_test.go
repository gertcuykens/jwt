package jwt

import (
	"encoding/base64"
	"errors"
	"testing"

	"github.com/google/go-cmp/cmp"
)

func TestBase64(t *testing.T) {
	type T struct {
		X string `json:"x,omitempty"`
	}

	testCases := []struct {
		test     T
		expected string
	}{
		{T{}, ""},
		{T{"test"}, "test"},
	}

	for _, tc := range testCases {
		t.Run(tc.expected, func(t *testing.T) {
			b64, err := marshal(tc.test)
			if err != nil {
				t.Error(err)
			}
			t.Logf("%s", b64)

			var dt T
			err = unmarshal(b64, &dt)
			if errors.As(err, new(base64.CorruptInputError)) {
				t.Errorf("%s", err)
			}

			if want, got := tc.expected, dt.X; want != got {
				t.Errorf("unmarshal (-want +got):\n%s", cmp.Diff(want, got))
			}
		})
	}

}
