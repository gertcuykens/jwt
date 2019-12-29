package jwt

import (
	"errors"
	"time"
)

var (
	ErrValidAud = errors.New("invalid aud")
	ErrValidExp = errors.New("invalid exp")
	ErrValidIat = errors.New("invalid iat")
	ErrValidIss = errors.New("invalid iss")
	ErrValidJti = errors.New("invalid jti")
	ErrValidNbf = errors.New("invalid nbf")
	ErrValidSub = errors.New("invalid sub")
)

type Validator func(Payload) error

func ValidAudience(aud Audience) Validator {
	return func(pl Payload) error {
		for _, serverAud := range aud {
			for _, clientAud := range pl.Audience {
				if clientAud == serverAud {
					return nil
				}
			}
		}
		return ErrValidAud
	}
}

func ValidExpirationTime(now time.Time) Validator {
	return func(pl Payload) error {
		if pl.ExpirationTime == nil || NumericDate(now).After(pl.ExpirationTime.Time) {
			return ErrValidExp
		}
		return nil
	}
}

func ValidIssuedAt(now time.Time) Validator {
	return func(pl Payload) error {
		if pl.IssuedAt != nil && NumericDate(now).Before(pl.IssuedAt.Time) {
			return ErrValidIat
		}
		return nil
	}
}

func ValidIssuer(iss string) Validator {
	return func(pl Payload) error {
		if pl.Issuer != iss {
			return ErrValidIss
		}
		return nil
	}
}

func ValidID(jti string) Validator {
	return func(pl Payload) error {
		if pl.JWTID != jti {
			return ErrValidJti
		}
		return nil
	}
}

func ValidNotBefore(now time.Time) Validator {
	return func(pl Payload) error {
		if pl.NotBefore != nil && NumericDate(now).Before(pl.NotBefore.Time) {
			return ErrValidNbf
		}
		return nil
	}
}

func ValidSubject(sub string) Validator {
	return func(pl Payload) error {
		if pl.Subject != sub {
			return ErrValidSub
		}
		return nil
	}
}

func Validate(pl Payload, vs ...Validator) error {
	var err error
	for _, v := range vs {
		if err = v(pl); err != nil {
			return err
		}
	}
	return nil
}
