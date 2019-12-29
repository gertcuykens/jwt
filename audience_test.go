package jwt

import (
	"testing"

	"github.com/google/go-cmp/cmp"
)

func TestAudienceMarshalJSON(t *testing.T) {
	c := []struct {
		a Audience
		b string
	}{
		{Audience{}, `""`},
		{Audience{"0"}, `"0"`},
		{Audience{"0", "1"}, `["0","1"]`},
	}
	for _, n := range c {
		t.Run("", func(t *testing.T) {
			b, err := n.a.MarshalJSON()
			if err != nil {
				t.Fatal(err)
			}
			if n.b != string(b) {
				t.Errorf(cmp.Diff(n.b, string(b)))
			}
		})
	}
}

func TestAudienceUnmarshalJSON(t *testing.T) {
	c := []struct {
		a Audience
		b []byte
	}{
		{Audience{}, nil},
		{Audience{"0"}, []byte(`"0"`)},
		{Audience{"0", "1"}, []byte(`["0","1"]`)},
	}
	for _, n := range c {
		t.Run("", func(t *testing.T) {
			a := Audience{}
			err := a.UnmarshalJSON(n.b)
			if err != nil && n.b != nil {
				t.Fatal(err)
			}
			if d := cmp.Diff(n.a, a); d != "" {
				t.Errorf(d)
			}
		})
	}
}
