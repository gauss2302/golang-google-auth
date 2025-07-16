package middleware

import (
	"fmt"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"googleAuth/internal/service"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
)

// AuthMiddleware provides JWT token validation middleware
func AuthMiddleware(jwtSecret string) gin.HandlerFunc {
	return func(c *gin.Context) {
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			c.JSON(http.StatusUnauthorized, gin.H{
				"error": "Authorization header required",
				"code":  "MISSING_AUTH_HEADER",
			})
			c.Abort()
			return
		}

		const bearerPrefix = "Bearer "
		if !strings.HasPrefix(authHeader, bearerPrefix) {
			c.JSON(http.StatusUnauthorized, gin.H{
				"error": "Bearer token required",
				"code":  "INVALID_AUTH_FORMAT",
			})
			c.Abort()
			return
		}

		tokenString := strings.TrimPrefix(authHeader, bearerPrefix)
		if tokenString == "" {
			c.JSON(http.StatusUnauthorized, gin.H{
				"error": "Token cannot be empty",
				"code":  "EMPTY_TOKEN",
			})
			c.Abort()
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
			c.JSON(http.StatusUnauthorized, gin.H{
				"error": "Invalid token",
				"code":  "TOKEN_INVALID",
			})
			c.Abort()
			return
		}

		// Извлекаем claims и устанавливаем в контекст
		claims, ok := token.Claims.(*service.Claims)
		if !ok || !token.Valid {
			c.JSON(http.StatusUnauthorized, gin.H{
				"error": "Invalid token claims",
				"code":  "INVALID_CLAIMS",
			})
			c.Abort()
			return
		}

		if err := validateTokenClaims(claims); err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{
				"error": "Token validation failed",
				"code":  "CLAIM_VALIDATION_FAILED",
			})
			c.Abort()
			return
		}

		c.Set("user_id", claims.UserID)
		c.Set("session_id", claims.SessionID)
		c.Set("token_type", claims.TokenType)
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

	if claims.SessionID == "" {
		return fmt.Errorf("missing session ID")
	}

	return nil
}
