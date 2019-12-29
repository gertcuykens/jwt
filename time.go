package jwt

import (
	"encoding/json"
	"time"
)

var Epoch = time.Date(1970, time.January, 1, 0, 0, 0, 0, time.UTC)

type Time struct {
	time.Time
}

func NumericDate(tt time.Time) *Time {
	if tt.Before(Epoch) {
		tt = Epoch
	}
	return &Time{time.Unix(tt.Unix(), 0)}
}

func (t Time) MarshalJSON() ([]byte, error) {
	if t.Before(Epoch) {
		return json.Marshal(0)
	}
	return json.Marshal(t.Unix())
}

func (t *Time) UnmarshalJSON(b []byte) error {
	var unix *int64
	if err := json.Unmarshal(b, &unix); err != nil {
		return err
	}
	if unix == nil {
		return nil
	}
	tt := time.Unix(*unix, 0)
	if tt.Before(Epoch) {
		tt = Epoch
	}
	t.Time = tt
	return nil
}
