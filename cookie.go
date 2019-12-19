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
)

type Cookie string

func SignCookie(iss string, aud []string, c Algorithm, fn http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()

		cookie, err := r.Cookie("Authorization")
		if err != nil {
			ctx = context.WithValue(ctx, Cookie("Error"), err)
			fn(w, r.WithContext(ctx))
			return
		}

		now := time.Now()
		pl := Payload{
			Issuer:         iss,
			Subject:        cookie.Value,
			Audience:       Audience(aud),
			ExpirationTime: NumericDate(now.Add(time.Hour)),
			IssuedAt:       NumericDate(now),
			JWTID:          randS64(),
		}

		token, err := Sign(pl, c)
		if err != nil {
			ctx = context.WithValue(ctx, Cookie("Error"), err)
			fn(w, r.WithContext(ctx))
			return
		}

		ctx = context.WithValue(ctx, Cookie("Authorization"), string(token))
		fn(w, r.WithContext(ctx))
	}
}

func VerifyCookie(iss string, aud []string, c Algorithm, fn http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()

		cookie, err := r.Cookie("Authorization")
		if err != nil {
			ctx = context.WithValue(ctx, Cookie("Error"), err)
			fn(w, r.WithContext(ctx))
			return
		}

		var (
			pl           Payload
			now          = time.Now()
			hdValidator  = ValidateHeader
			iatValidator = IssuedAtValidator(now)
			expValidator = ExpirationTimeValidator(now)
			issValidator = IssuerValidator(iss)
			audValidator = AudienceValidator(Audience(aud))
			plValidator  = ValidatePayload(&pl, iatValidator, expValidator, issValidator, audValidator)
		)

		_, err = Verify([]byte(cookie.Value), c, &pl, hdValidator, plValidator)
		if err != nil {
			ctx = context.WithValue(ctx, Cookie("Error"), err)
			fn(w, r.WithContext(ctx))
			return
		}

		ctx = context.WithValue(ctx, Cookie("Authorization"), Payload(pl))
		fn(w, r.WithContext(ctx))
	}
}

func Verify25519(iss string, fn http.HandlerFunc) http.HandlerFunc {
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

		var pl Payload
		err = json.Unmarshal(t1, &pl)
		if err != nil {
			ctx = context.WithValue(ctx, Cookie("Error"), err)
			fn(w, r.WithContext(ctx))
			return
		}

		ctx = context.WithValue(ctx, Cookie("Authorization"), pl)

		t2, err := base64.RawURLEncoding.DecodeString(t[2])
		if err != nil {
			ctx = context.WithValue(ctx, Cookie("Error"), err)
			fn(w, r.WithContext(ctx))
			return
		}

		rp, err := http.NewRequest("GET", iss, nil)
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

		fn(w, r.WithContext(ctx))
	}
}

func VerifyRawCookie(key string, c Algorithm, fn http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()

		cookie, err := r.Cookie(key)
		if err != nil {
			ctx = context.WithValue(ctx, Cookie("Error"), err)
			fn(w, r.WithContext(ctx))
			return
		}

		sig := strings.Split(cookie.Value, ".")
		if len(sig) < 2 {
			ctx = context.WithValue(ctx, Cookie("Error"), errors.New("no signiture"))
			fn(w, r.WithContext(ctx))
			return
		}

		err = c.Verify([]byte(sig[0]), []byte(sig[1]))
		if err != nil {
			ctx = context.WithValue(ctx, Cookie("Error"), err)
			fn(w, r.WithContext(ctx))
			return
		}

		ctx = context.WithValue(ctx, Cookie(key), sig[0])
		fn(w, r.WithContext(ctx))
	}
}
