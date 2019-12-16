package jwt

import (
	"errors"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
)

func TestValidators(t *testing.T) {
	now := time.Now()
	iat := NumericDate(now)
	exp := NumericDate(now.Add(24 * time.Hour))
	nbf := NumericDate(now.Add(15 * time.Second))
	jti := "jti"
	aud := Audience{"aud", "aud1", "aud2", "aud3"}
	sub := "sub"
	iss := "iss"
	testCases := []struct {
		claim string
		pl    *Payload
		vl    Validator
		err   error
	}{
		{"iss", &Payload{Issuer: iss}, IssuerValidator("iss"), nil},
		{"iss", &Payload{Issuer: iss}, IssuerValidator("not_iss"), ErrIssValidation},
		{"sub", &Payload{Subject: sub}, SubjectValidator("sub"), nil},
		{"sub", &Payload{Subject: sub}, SubjectValidator("not_sub"), ErrSubValidation},
		{"aud", &Payload{Audience: aud}, AudienceValidator(Audience{"aud"}), nil},
		{"aud", &Payload{Audience: aud}, AudienceValidator(Audience{"foo", "aud1"}), nil},
		{"aud", &Payload{Audience: aud}, AudienceValidator(Audience{"bar", "aud2"}), nil},
		{"aud", &Payload{Audience: aud}, AudienceValidator(Audience{"baz", "aud3"}), nil},
		{"aud", &Payload{Audience: aud}, AudienceValidator(Audience{"qux", "aud4"}), ErrAudValidation},
		{"aud", &Payload{Audience: aud}, AudienceValidator(Audience{"not_aud"}), ErrAudValidation},
		{"exp", &Payload{ExpirationTime: exp}, ExpirationTimeValidator(now), nil},
		{"exp", &Payload{ExpirationTime: exp}, ExpirationTimeValidator(time.Unix(now.Unix()-int64(24*time.Hour), 0)), nil},
		{"exp", &Payload{ExpirationTime: exp}, ExpirationTimeValidator(time.Unix(now.Unix()+int64(24*time.Hour), 0)), ErrExpValidation},
		{"exp", &Payload{}, ExpirationTimeValidator(time.Now()), ErrExpValidation},
		{"nbf", &Payload{NotBefore: nbf}, NotBeforeValidator(now), ErrNbfValidation},
		{"nbf", &Payload{NotBefore: nbf}, NotBeforeValidator(time.Unix(now.Unix()+int64(15*time.Second), 0)), nil},
		{"nbf", &Payload{NotBefore: nbf}, NotBeforeValidator(time.Unix(now.Unix()-int64(15*time.Second), 0)), ErrNbfValidation},
		{"nbf", &Payload{}, NotBeforeValidator(time.Now()), nil},
		{"iat", &Payload{IssuedAt: iat}, IssuedAtValidator(now), nil},
		{"iat", &Payload{IssuedAt: iat}, IssuedAtValidator(time.Unix(now.Unix()+1, 0)), nil},
		{"iat", &Payload{IssuedAt: iat}, IssuedAtValidator(time.Unix(now.Unix()-1, 0)), ErrIatValidation},
		{"iat", &Payload{}, IssuedAtValidator(time.Now()), nil},
		{"jti", &Payload{JWTID: jti}, IDValidator("jti"), nil},
		{"jti", &Payload{JWTID: jti}, IDValidator("not_jti"), ErrJtiValidation},
	}
	for _, tc := range testCases {
		t.Run(tc.claim, func(t *testing.T) {
			if want, got := tc.err, tc.vl(tc.pl); !errors.Is(got, want) {
				t.Errorf(cmp.Diff(want, got))
			}
		})
	}
}
