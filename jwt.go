package jwt

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/gbrlsnchs/jwt/v3"
)

type Cookie string

type Authorization jwt.Payload

type Algorithm jwt.Algorithm

func Sign(iss string, aud []string, c Algorithm, fn http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()

		cookie, err := r.Cookie("Authorization")
		if err != nil {
			ctx = context.WithValue(ctx, Cookie("Error"), err)
			fn(w, r.WithContext(ctx))
			return
		}

		now := time.Now()
		pl := Authorization{
			Issuer:         iss,
			Subject:        cookie.Value,
			Audience:       jwt.Audience(aud),
			ExpirationTime: jwt.NumericDate(now.Add(time.Hour)),
			IssuedAt:       jwt.NumericDate(now),
			JWTID:          randS64(),
		}

		token, err := jwt.Sign(pl, c)
		if err != nil {
			ctx = context.WithValue(ctx, Cookie("Error"), err)
			fn(w, r.WithContext(ctx))
			return
		}

		ctx = context.WithValue(ctx, Cookie("Authorization"), string(token))
		fn(w, r.WithContext(ctx))
	}
}

func Verify(iss string, c Algorithm, fn http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()

		cookie, err := r.Cookie("Authorization")
		if err != nil {
			ctx = context.WithValue(ctx, Cookie("Error"), err)
			fn(w, r.WithContext(ctx))
			return
		}

		var (
			pl           jwt.Payload
			now          = time.Now()
			hdValidator  = jwt.ValidateHeader
			iatValidator = jwt.IssuedAtValidator(now)
			expValidator = jwt.ExpirationTimeValidator(now)
			issValidator = jwt.IssuerValidator(iss)
			audValidator = jwt.AudienceValidator(jwt.Audience{r.Referer()})
			plValidator  = jwt.ValidatePayload(&pl, iatValidator, expValidator, issValidator, audValidator)
		)

		_, err = jwt.Verify([]byte(cookie.Value), c, &pl, hdValidator, plValidator)
		if err != nil {
			ctx = context.WithValue(ctx, Cookie("Error"), err)
			fn(w, r.WithContext(ctx))
			return
		}

		ctx = context.WithValue(ctx, Cookie("Authorization"), Authorization(pl))
		fn(w, r.WithContext(ctx))
	}
}

func Verify25519(fn http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()

		cookie, err := r.Cookie("Authorization")
		if err != nil {
			ctx = context.WithValue(ctx, Cookie("Error"), err)
			fn(w, r.WithContext(ctx))
			return
		}

		t := strings.Split(cookie.Value, ".")
		if len(t) < 3 {
			ctx = context.WithValue(ctx, Cookie("Error"), errors.New("token invalid"))
			fn(w, r.WithContext(ctx))
			return
		}

		t1, err := base64.RawURLEncoding.DecodeString(t[1])
		if err != nil {
			ctx = context.WithValue(ctx, Cookie("Error"), err)
			fn(w, r.WithContext(ctx))
			return
		}

		var pl Authorization
		err = json.Unmarshal(t1, &pl)
		if err != nil {
			ctx = context.WithValue(ctx, Cookie("Error"), err)
			fn(w, r.WithContext(ctx))
			return
		}

		t2, err := base64.RawURLEncoding.DecodeString(t[2])
		if err != nil {
			ctx = context.WithValue(ctx, Cookie("Error"), err)
			fn(w, r.WithContext(ctx))
			return
		}

		rp, err := http.NewRequest("GET", pl.Issuer, nil)
		if err != nil {
			ctx = context.WithValue(ctx, Cookie("Error"), err)
			fn(w, r.WithContext(ctx))
			return
		}

		var public ed25519.PublicKey
		err = get(rp, func(b []byte) { public = decodePublicKey(b) })
		if err != nil || public == nil {
			ctx = context.WithValue(ctx, Cookie("Error"), fmt.Errorf("public nil: %w", err))
			fn(w, r.WithContext(ctx))
			return
		}

		valid := ed25519.Verify(public, []byte(t[0]+"."+t[1]), t2)
		if !valid {
			ctx = context.WithValue(ctx, Cookie("Error"), errors.New("ed25519 invalid"))
			fn(w, r.WithContext(ctx))
			return
		}

		ctx = context.WithValue(ctx, Cookie("Authorization"), pl)
		fn(w, r.WithContext(ctx))
	}
}
