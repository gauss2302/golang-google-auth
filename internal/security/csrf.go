package security

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/rs/zerolog/log"
)

const (
	CSRFTokenLength = 32
	CSRFCookieName  = "csrf_token"
	CSRFHeaderName  = "X-CSRF-Token"
	CSRFFormField   = "csrf_token"
)

var (
	ErrInvalidCSRFToken = errors.New("invalid CSRF token")
	ErrMissingCSRFToken = errors.New("missing CSRF token")
)

type CSRFConfig struct {
	Key            []byte
	CookieSecure   bool
	CookiePath     string
	CookieDomain   string
	CookieMaxAge   int
	CookieSameSite http.SameSite
}

type CSRFProtection struct {
	config CSRFConfig
}

func NewCSRFProtection(config CSRFConfig) *CSRFProtection {
	if len(config.Key) == 0 {
		panic("CSRF key cannot be empty")
	}

	if config.CookiePath == "" {
		config.CookiePath = "/"
	}
	if config.CookieMaxAge == 0 {
		config.CookieMaxAge = 86400 // 24 hours
	}
	if config.CookieSameSite == 0 {
		config.CookieSameSite = http.SameSiteStrictMode
	}

	return &CSRFProtection{
		config: config,
	}
}

// Gin middleware for CSRF protection
func (c *CSRFProtection) GinMiddleware() gin.HandlerFunc {
	return func(ctx *gin.Context) {
		r := ctx.Request
		w := ctx.Writer

		// Safe methods - just set CSRF token
		if r.Method == http.MethodGet ||
			r.Method == http.MethodHead ||
			r.Method == http.MethodOptions ||
			r.Method == http.MethodTrace {

			cookie, err := r.Cookie(CSRFCookieName)
			if err != nil || cookie.Value == "" {
				token, err := c.generateToken()
				if err != nil {
					ctx.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate CSRF token"})
					ctx.Abort()
					return
				}

				http.SetCookie(w, &http.Cookie{
					Name:     CSRFCookieName,
					Value:    token,
					Path:     c.config.CookiePath,
					Domain:   c.config.CookieDomain,
					MaxAge:   c.config.CookieMaxAge,
					Secure:   c.config.CookieSecure,
					HttpOnly: true,
					SameSite: c.config.CookieSameSite,
				})

				// Make token available to the handler
				ctx.Set("csrf_token", token)
			} else {
				ctx.Set("csrf_token", cookie.Value)
			}

			ctx.Next()
			return
		}

		// Validation for unsafe methods
		cookie, err := r.Cookie(CSRFCookieName)
		if err != nil || cookie.Value == "" {
			log.Error().Err(err).Msg("CSRF token cookie missing")
			ctx.JSON(http.StatusForbidden, gin.H{"error": "CSRF token is missing"})
			ctx.Abort()
			return
		}

		// Check header or form for the token
		var token string
		if headerToken := r.Header.Get(CSRFHeaderName); headerToken != "" {
			token = headerToken
		} else if formToken := r.FormValue(CSRFFormField); formToken != "" {
			token = formToken
		} else {
			log.Error().Msg("CSRF token is not in header or form")
			ctx.JSON(http.StatusForbidden, gin.H{"error": "CSRF token is missing"})
			ctx.Abort()
			return
		}

		// Validation
		if err := c.validateToken(token); err != nil {
			log.Error().Err(err).Msg("CSRF token validation failed")
			ctx.JSON(http.StatusForbidden, gin.H{"error": "Invalid CSRF token"})
			ctx.Abort()
			return
		}

		ctx.Next()
	}
}

// Standard HTTP middleware for CSRF protection
func (c *CSRFProtection) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet ||
			r.Method == http.MethodHead ||
			r.Method == http.MethodOptions ||
			r.Method == http.MethodTrace {

			cookie, err := r.Cookie(CSRFCookieName)
			if err != nil || cookie.Value == "" {
				token, err := c.generateToken()
				if err != nil {
					http.Error(w, "Failed to generate CSRF token", http.StatusInternalServerError)
					return
				}

				http.SetCookie(w, &http.Cookie{
					Name:     CSRFCookieName,
					Value:    token,
					Path:     c.config.CookiePath,
					Domain:   c.config.CookieDomain,
					MaxAge:   c.config.CookieMaxAge,
					Secure:   c.config.CookieSecure,
					HttpOnly: true,
					SameSite: c.config.CookieSameSite,
				})
			}
			next.ServeHTTP(w, r)
			return
		}

		// Validation for other methods
		cookie, err := r.Cookie(CSRFCookieName)
		if err != nil || cookie.Value == "" {
			log.Error().Err(err).Msg("CSRF token cookie missing")
			http.Error(w, "CSRF token is missing", http.StatusForbidden)
			return
		}

		// Check header or form for the token
		var token string
		if headerToken := r.Header.Get(CSRFHeaderName); headerToken != "" {
			token = headerToken
		} else if formToken := r.FormValue(CSRFFormField); formToken != "" {
			token = formToken
		} else {
			log.Error().Msg("CSRF token is not in header or form")
			http.Error(w, "CSRF token is missing", http.StatusForbidden)
			return
		}

		// Validation
		if err := c.validateToken(token); err != nil {
			log.Error().Err(err).Msg("CSRF token validation failed")
			http.Error(w, "Invalid CSRF token", http.StatusForbidden)
			return
		}

		next.ServeHTTP(w, r)
	})
}

func (c *CSRFProtection) generateToken() (string, error) {
	randomBytes := make([]byte, CSRFTokenLength)
	if _, err := rand.Read(randomBytes); err != nil {
		return "", err
	}

	randomString := base64.StdEncoding.EncodeToString(randomBytes)

	// Payload and time
	timeStamp := time.Now().Unix()
	payload := fmt.Sprintf("%s|%d", randomString, timeStamp)

	// Sign
	h := hmac.New(sha256.New, c.config.Key)
	h.Write([]byte(payload))
	sign := base64.StdEncoding.EncodeToString(h.Sum(nil))

	// Payload + sign
	token := fmt.Sprintf("%s|%s", payload, sign)

	return token, nil
}

func (c *CSRFProtection) validateToken(token string) error {
	if token == "" {
		return ErrMissingCSRFToken
	}

	// Split token into signature and payload
	parts := strings.Split(token, "|")
	if len(parts) != 3 {
		return ErrInvalidCSRFToken
	}

	// Extraction
	randomStr, timeStampStr, receivedSign := parts[0], parts[1], parts[2]
	payload := fmt.Sprintf("%s|%s", randomStr, timeStampStr)

	// Sign payload with HMAC 256
	h := hmac.New(sha256.New, c.config.Key)
	h.Write([]byte(payload))
	expectedSign := base64.StdEncoding.EncodeToString(h.Sum(nil))

	// Compare
	if !hmac.Equal([]byte(receivedSign), []byte(expectedSign)) {
		return ErrInvalidCSRFToken
	}
	return nil
}

// GetToken returns the CSRF token from the context (Gin)
func GetCSRFToken(c *gin.Context) string {
	if token, exists := c.Get("csrf_token"); exists {
		return token.(string)
	}
	return ""
}
