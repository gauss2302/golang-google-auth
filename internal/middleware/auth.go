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
		switch {
		case authHeader == "":
			abortJSON(c, http.StatusUnauthorized, "Authorization header required", "MISSING_AUTH_HEADER")
			return
		default:
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

			// Парсим и валидируем JWT токен
			token, err := jwt.ParseWithClaims(tokenString, &service.Claims{}, func(token *jwt.Token) (interface{}, error) {
				if method, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
					return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
				} else if method != jwt.SigningMethodHS256 {
					return nil, fmt.Errorf("unexpected HMAC algorithm: %v", method.Alg())
				}
				return []byte(jwtSecret), nil
			})

			if err != nil {
			if errors.Is(err, jwt.ErrTokenExpired) {
					abortJSON(c, http.StatusUnauthorized, "Token expired", "TOKEN_EXPIRED")
					return
				}
				abortJSON(c, http.StatusUnauthorized, "Invalid token", "TOKEN_INVALID")
				return
			}

			// Извлекаем claims и устанавливаем в контекст
			claims, ok := token.Claims.(*service.Claims)
			if !ok || !token.Valid {
				abortJSON(c, http.StatusUnauthorized, "Invalid token claims", "INVALID_CLAIMS")
				return
			}

			if err := validateTokenClaims(claims); err != nil {
				abortJSON(c, http.StatusUnauthorized, "Token validation failed", "CLAIM_VALIDATION_FAILED")
				return
			}

			c.Set("user_id", claims.UserID)
			c.Set("session_id", claims.SessionID)
			c.Set("token_type", claims.TokenType)
		}
	}
}

func validateTokenClaims(claims *service.Claims) error {
	now := time.Now()

	if claims.ExpiresAt != nil && now.After(claims.ExpiresAt.Time) {
		return fmt.Errorf("token has expired")
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

func abortJSON(c *gin.Context, code int, message, errorCode string) {
	c.JSON(code, gin.H{
		"error": message,
		"code":  errorCode,
	})
	c.Abort()
}
