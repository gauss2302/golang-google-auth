package middleware

import (
	"errors"
	"fmt"
	"googleAuth/internal/service"
	"net/http"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"

	"github.com/gin-gonic/gin"
)

func AuthMiddleware(jwtSecret string) gin.HandlerFunc {
	return func(c *gin.Context) {
		authHeader := strings.TrimSpace(c.GetHeader("Authorization"))
		if authHeader == "" {
			abortJSON(c, http.StatusUnauthorized, "Authorization header required", "MISSING_AUTH_HEADER")
			return
		}

		const bearerPrefix = "Bearer "
		tokenString, ok := strings.CutPrefix(authHeader, bearerPrefix)
		if !ok {
			abortJSON(c, http.StatusUnauthorized, "Bearer token required", "INVALID_AUTH_FORMAT")
			return
		}

		tokenString = strings.TrimSpace(tokenString)
		if tokenString == "" {
			abortJSON(c, http.StatusUnauthorized, "Token cannot be empty", "EMPTY_TOKEN")
			return
		}

		claims, err := parseAndValidateToken(tokenString, jwtSecret)
		if err != nil {
			handleTokenError(c, err)
			return
		}

		c.Set("user_id", claims.UserID)
		c.Set("session_id", claims.SessionID)
		c.Set("token_type", claims.TokenType)
		c.Set("authenticated", true)

		c.Next()
	}
}

// OptionalAuthMiddleware tries to authenticate but doesn't fail if no token
func OptionalAuthMiddleware(jwtSecret string) gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Set("authenticated", false)

		authHeader := strings.TrimSpace(c.GetHeader("Authorization"))
		if authHeader == "" {
			c.Next()
			return
		}

		const bearerPrefix = "Bearer "
		tokenString, ok := strings.CutPrefix(authHeader, bearerPrefix)
		if !ok {
			c.Next()
			return
		}

		tokenString = strings.TrimSpace(tokenString)
		if tokenString == "" {
			c.Next()
			return
		}

		claims, err := parseAndValidateToken(tokenString, jwtSecret)
		if err != nil {
			// For optional auth, we just continue without setting user
			c.Next()
			return
		}

		c.Set("user_id", claims.UserID)
		c.Set("session_id", claims.SessionID)
		c.Set("token_type", claims.TokenType)
		c.Set("authenticated", true)

		c.Next()
	}
}



func parseAndValidateToken(tokenString, jwtSecret string) (*service.Claims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &service.Claims{}, func(token *jwt.Token) (interface{}, error) {
		if method, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		} else if method != jwt.SigningMethodHS256 {
			return nil, fmt.Errorf("unexpected HMAC algorithm: %v", method.Alg())
		}
		return []byte(jwtSecret), nil
	})

	if err != nil {
		return nil, err
	}

	claims, ok := token.Claims.(*service.Claims)
	if !ok || !token.Valid {
		return nil, fmt.Errorf("invalid token claims")
	}

	if err := validateTokenClaims(claims); err != nil {
		return nil, err
	}

	return claims, nil
}

func validateTokenClaims(claims *service.Claims) error {
	now := time.Now()

	if claims.ExpiresAt != nil && now.After(claims.ExpiresAt.Time) {
		return jwt.ErrTokenExpired
	}

	if claims.NotBefore != nil && now.Before(claims.NotBefore.Time) {
		return fmt.Errorf("token not valid yet")
	}

	if claims.TokenType != "access" {
		return fmt.Errorf("invalid token type: expected access, got %s", claims.TokenType)
	}

	if claims.UserID == uuid.Nil {
		return fmt.Errorf("invalid user ID")
	}

	if _, err := uuid.Parse(claims.SessionID); err != nil {
		return fmt.Errorf("invalid session ID")
	}

	return nil
}

func handleTokenError(c *gin.Context, err error) {
	if errors.Is(err, jwt.ErrTokenExpired) {
		abortJSON(c, http.StatusUnauthorized, "Token expired", "TOKEN_EXPIRED")
		return
	}
	abortJSON(c, http.StatusUnauthorized, "Invalid token", "TOKEN_INVALID")
}

func abortJSON(c *gin.Context, code int, message, errorCode string) {
	c.JSON(code, gin.H{
		"error": message,
		"code":  errorCode,
	})
	c.Abort()
}