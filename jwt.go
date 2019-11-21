package jwt

import (
	"context"
	"net/http"
	"os"
	"time"

	"github.com/gbrlsnchs/jwt/v3"
)

type Cookie string

type Authorization jwt.Payload

func Sign(c jwt.Algorithm, fn http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		cookie, err := r.Cookie("Authorization")
		if err != nil {
			jsonResponse(w, err.Error(), http.StatusUnauthorized)
			return
		}

		now := time.Now()
		pl := Authorization{
			Issuer:         r.Referer(),
			Subject:        cookie.Value,
			Audience:       jwt.Audience{os.Getenv("ORIGIN")},
			ExpirationTime: jwt.NumericDate(now.Add(time.Hour)),
			IssuedAt:       jwt.NumericDate(now),
			JWTID:          randS64(),
		}

		token, err := jwt.Sign(pl, c)
		if err != nil {
			jsonResponse(w, err.Error(), http.StatusInternalServerError)
			return
		}

		ctx := r.Context()
		ctx = context.WithValue(ctx, Cookie("Authorization"), string(token))
		r = r.WithContext(ctx)

		fn(w, r)
	}
}

func Verify(c jwt.Algorithm, fn http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		cookie, err := r.Cookie("Authorization")
		if err != nil {
			jsonResponse(w, err.Error(), http.StatusUnauthorized)
			return
		}

		var (
			pl           jwt.Payload
			now          = time.Now()
			hdValidator  = jwt.ValidateHeader
			iatValidator = jwt.IssuedAtValidator(now)
			expValidator = jwt.ExpirationTimeValidator(now)
			audValidator = jwt.AudienceValidator(jwt.Audience{os.Getenv("ORIGIN")})
			plValidator  = jwt.ValidatePayload(&pl, iatValidator, expValidator, audValidator)
		)

		_, err = jwt.Verify([]byte(cookie.Value), c, &pl, hdValidator, plValidator)

		ctx := r.Context()
		ctx = context.WithValue(ctx, Cookie("Error"), err)
		r = r.WithContext(ctx)

		fn(w, r)
	}
}
