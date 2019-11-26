package jwt

import (
	"context"
	"net/http"
	"net/url"
	"time"

	"github.com/gbrlsnchs/jwt/v3"
)

type Cookie string

type Authorization jwt.Payload

type Algorithm jwt.Algorithm

func Sign(iss string, c Algorithm, fn http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		cookie, err := r.Cookie("Authorization")
		if err != nil {
			jsonResponse(w, err.Error(), http.StatusUnauthorized)
			return
		}

		ref, err := url.Parse(r.Referer())
		if err != nil {
			jsonResponse(w, err.Error(), http.StatusUnauthorized)
			return
		}

		now := time.Now()
		pl := Authorization{
			Issuer:         iss,
			Subject:        cookie.Value,
			Audience:       jwt.Audience{referer(ref)},
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

func Verify(iss string, c Algorithm, fn http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		cookie, err := r.Cookie("Authorization")
		if err != nil {
			jsonResponse(w, err.Error(), http.StatusUnauthorized)
			return
		}

		ref, err := url.Parse(r.Referer())
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
			issValidator = jwt.IssuerValidator(iss)
			audValidator = jwt.AudienceValidator(jwt.Audience{referer(ref)})
			plValidator  = jwt.ValidatePayload(&pl, iatValidator, expValidator, issValidator, audValidator)
		)

		_, err = jwt.Verify([]byte(cookie.Value), c, &pl, hdValidator, plValidator)

		ctx := r.Context()
		ctx = context.WithValue(ctx, Cookie("Error"), err)
		r = r.WithContext(ctx)

		fn(w, r)
	}
}
