package middleware

import (
	"googleAuth/internal/domain"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
)

// AuthMiddleware provides JWT token validation middleware
func AuthMiddleware(jwtSecret string, authService domain.AuthenticationService) gin.HandlerFunc {
	return func(c *gin.Context) {
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Authorization header required"})
			c.Abort()
			return
		}

		tokenString := strings.TrimPrefix(authHeader, "Bearer ")
		if tokenString == authHeader {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Bearer token required"})
			c.Abort()
			return
		}

		// Validate token and get authenticated user information
		authInfo, err := authService.ValidateAccessTokenWithDetails(tokenString)
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid or expired token"})
			c.Abort()
			return
		}

		// Set user context for subsequent handlers
		c.Set("user_id", authInfo.UserID)
		c.Set("session_id", authInfo.SessionID)

		c.Next()
	}
}
