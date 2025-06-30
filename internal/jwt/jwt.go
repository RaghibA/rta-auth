package jwt

import (
	"context"
	"errors"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/RaghibA/telemetrix-authn/internal/utils"
	"github.com/golang-jwt/jwt/v5"
)

type contextKey string

const UserKey contextKey = "userId"

// GenerateCookie generates a JWT token string for a given user ID and expiration time.
// Params:
// - userId: string - the ID of the user
// - exp: time.Time - the expiration time of the token
// Returns:
// - string: the generated JWT token string
// - error: error if any occurred during token generation
func GenerateCookie(userId string, exp time.Time) (string, error) {
	jwtSecret, err := utils.GetEnv("JWT_SECRET", "")
	if err != nil {
		return "", err
	}

	if userId == "" {
		return "", errors.New("error generating cookie: no user id provided")
	}

	claims := jwt.MapClaims{
		"sub": userId,
		"iat": time.Now().Unix(),
		"exp": exp.Unix(),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	tokenString, err := token.SignedString([]byte(jwtSecret))
	if err != nil {
		return "", err
	}

	return tokenString, nil
}

// GenerateAccessToken generates a JWT access token string for a given user ID and expiration time with permissions.
// Params:
// - userId: string - the ID of the user
// - exp: time.Time - the expiration time of the token
// Returns:
// - string: the generated JWT access token string
// - error: error if any occurred during token generation
func GenerateAccessToken(userId string, exp time.Time) (string, error) {
	jwtSecret, err := utils.GetEnv("JWT_SECRET", "")
	if err != nil {
		return "", err
	}

	if userId == "" {
		return "", errors.New("error generating cookie: no user id provided")
	}

	claims := jwt.MapClaims{
		"sub":         userId,
		"iat":         time.Now().Unix(),
		"exp":         exp.Unix(),
		"permissions": []string{"read", "write"},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	tokenString, err := token.SignedString([]byte(jwtSecret))
	if err != nil {
		return "", err
	}

	return tokenString, nil
}

// AuthWithCookie is a middleware function that authenticates requests using a JWT token stored in a cookie.
// Params:
// - handlerFunc: http.HandlerFunc - the HTTP handler function to wrap
// Returns:
// - http.HandlerFunc: the wrapped HTTP handler function
func AuthWithCookie(handlerFunc http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		cookie, err := r.Cookie("refresh_token")
		if err != nil {
			log.Println(err)
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		tokenString := cookie.Value

		secret, err := utils.GetEnv("JWT_SECRET", "")
		if err != nil {
			log.Println(err)
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}

		claims := jwt.MapClaims{}
		token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, errors.New("unexpected signing method")
			}
			return []byte(secret), nil
		})
		if err != nil {
			if err == jwt.ErrTokenExpired {
				log.Println(err)
				http.Error(w, "Token expired, log in to account.", http.StatusUnauthorized)
				return
			} else if !token.Valid {
				log.Println(err)
				http.Error(w, "Invalid Token", http.StatusUnauthorized)
				return
			} else {
				log.Println(err)
				http.Error(w, "Token error", http.StatusBadRequest)
				return
			}
		}

		exp, ok := claims["exp"].(float64)
		if ok {
			expTime := time.Unix(int64(exp), 0)
			if expTime.Before(time.Now()) {
				log.Println("Token Expired")
				http.Error(w, "Cookie Expired", http.StatusUnauthorized)
				return
			}
		} else {
			log.Println("no exp claim")
			http.Error(w, "Invalid cookie", http.StatusBadRequest)
			return
		}
		userId, ok := claims["sub"]
		if !ok {
			log.Println("No user id in claims")
			http.Error(w, "Missing Claims", http.StatusBadRequest)
			return
		}

		ctx := r.Context()
		ctx = context.WithValue(ctx, UserKey, userId)
		r = r.WithContext(ctx)

		handlerFunc(w, r)
	}
}

// AuthWithAccessToken is a function for authenticating requests using an access token.
// Params:
// - w: http.ResponseWriter - the HTTP response writer
// - r: *http.Request - the HTTP request
// Returns:
// - http.HandlerFunc: the wrapped HTTP handler function
func AuthWithAccessToken(handlerFunc http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var tokenString string
		authToken := r.Header.Get("Authorization")
		if authToken == "" {
			log.Println("No access token provided")
			http.Error(w, "Provide bearer token in Authorization header", http.StatusUnauthorized)
			return
		}
		const prefix = "Bearer "
		if strings.HasPrefix(authToken, prefix) {
			tokenString = strings.TrimPrefix(authToken, prefix)
		} else {
			http.Error(w, "Invalid access token", http.StatusUnauthorized)
		}

		// validate token from header
		secret, err := utils.GetEnv("JWT_SECRET", "")
		if err != nil {
			log.Println(err)
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}

		claims := jwt.MapClaims{}
		token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, errors.New("unexpected signing method")
			}
			return []byte(secret), nil
		})

		if token == nil {
			log.Fatal("Token is nil")
			http.Error(w, "No access token provided", http.StatusBadRequest)
			return
		}

		if err != nil {
			if err == jwt.ErrTokenExpired {
				log.Println(err)
				http.Error(w, "Token expired, log in to account.", http.StatusUnauthorized)
				return
			} else if !token.Valid {
				log.Println(err)
				http.Error(w, "Invalid Token", http.StatusUnauthorized)
				return
			} else {
				log.Println(err)
				http.Error(w, "Token error", http.StatusBadRequest)
				return
			}
		}

		exp, ok := claims["exp"].(float64)
		if ok {
			expTime := time.Unix(int64(exp), 0)
			if expTime.Before(time.Now()) {
				log.Println("Token Expired")
				http.Error(w, "Cookie Expired", http.StatusUnauthorized)
				return
			}
		} else {
			log.Println("no exp claim")
			http.Error(w, "Invalid cookie", http.StatusBadRequest)
			return
		}
		userId, ok := claims["sub"]
		if !ok {
			log.Println("No user id in claims")
			http.Error(w, "Missing Claims", http.StatusBadRequest)
			return
		}

		ctx := r.Context()
		ctx = context.WithValue(ctx, UserKey, userId)
		r = r.WithContext(ctx)

		handlerFunc(w, r)
	}
}
