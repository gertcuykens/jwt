package jwt

import "encoding/json"

// Audience RFC 7519.
type Audience []string

func (a Audience) MarshalJSON() ([]byte, error) {
	switch len(a) {
	case 0:
		return json.Marshal("")
	case 1:
		return json.Marshal(a[0])
	default:
		return json.Marshal([]string(a))
	}
}

func (a *Audience) UnmarshalJSON(b []byte) error {
	var v interface{}
	if err := json.Unmarshal(b, &v); err != nil {
		return err
	}
	switch w := v.(type) {
	case string:
		aud := make(Audience, 1)
		aud[0] = w
		*a = aud
	case []interface{}:
		aud := make(Audience, len(w))
		for i := range w {
			aud[i] = w[i].(string)
		}
		*a = aud
	}
	return nil
}
