package jwt

import (
	"errors"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
)

func Tests(t *testing.T) {
	now := time.Now()
	iat := NumericDate(now)
	exp := NumericDate(now.Add(24 * time.Hour))
	nbf := NumericDate(now.Add(15 * time.Second))
	jti := "jti"
	aud := Audience{"aud", "aud1", "aud2", "aud3"}
	sub := "sub"
	iss := "iss"
	testCases := []struct {
		pl  Payload
		vl  Validator
		err error
	}{
		{Payload{Issuer: iss}, ValidIssuer("iss"), nil},
		{Payload{Issuer: iss}, ValidIssuer("not_iss"), ErrValidIss},
		{Payload{Subject: sub}, ValidSubject("sub"), nil},
		{Payload{Subject: sub}, ValidSubject("not_sub"), ErrValidSub},
		{Payload{Audience: aud}, ValidAudience(Audience{"aud"}), nil},
		{Payload{Audience: aud}, ValidAudience(Audience{"foo", "aud1"}), nil},
		{Payload{Audience: aud}, ValidAudience(Audience{"bar", "aud2"}), nil},
		{Payload{Audience: aud}, ValidAudience(Audience{"baz", "aud3"}), nil},
		{Payload{Audience: aud}, ValidAudience(Audience{"qux", "aud4"}), ErrValidAud},
		{Payload{Audience: aud}, ValidAudience(Audience{"not_aud"}), ErrValidAud},
		{Payload{ExpirationTime: exp}, ValidExpirationTime(now), nil},
		{Payload{ExpirationTime: exp}, ValidExpirationTime(time.Unix(now.Unix()-int64(24*time.Hour), 0)), nil},
		{Payload{ExpirationTime: exp}, ValidExpirationTime(time.Unix(now.Unix()+int64(24*time.Hour), 0)), ErrValidExp},
		{Payload{}, ValidExpirationTime(time.Now()), ErrValidExp},
		{Payload{NotBefore: nbf}, ValidNotBefore(now), ErrValidNbf},
		{Payload{NotBefore: nbf}, ValidNotBefore(time.Unix(now.Unix()+int64(15*time.Second), 0)), nil},
		{Payload{NotBefore: nbf}, ValidNotBefore(time.Unix(now.Unix()-int64(15*time.Second), 0)), ErrValidNbf},
		{Payload{}, ValidNotBefore(time.Now()), nil},
		{Payload{IssuedAt: iat}, ValidIssuedAt(now), nil},
		{Payload{IssuedAt: iat}, ValidIssuedAt(time.Unix(now.Unix()+1, 0)), nil},
		{Payload{IssuedAt: iat}, ValidIssuedAt(time.Unix(now.Unix()-1, 0)), ErrValidIat},
		{Payload{}, ValidIssuedAt(time.Now()), nil},
		{Payload{JWTID: jti}, ValidID("jti"), nil},
		{Payload{JWTID: jti}, ValidID("not_jti"), ErrValidJti},
	}
	for _, tc := range testCases {
		t.Run("", func(t *testing.T) {
			if want, got := tc.err, tc.vl(tc.pl); !errors.Is(got, want) {
				t.Errorf(cmp.Diff(want, got))
			}
		})
	}
}
