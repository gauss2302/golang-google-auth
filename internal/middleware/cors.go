package middleware

import (
	"github.com/gin-gonic/gin"
)

func CORS() gin.HandlerFunc {
	return gin.HandlerFunc(func(c *gin.Context) {
		origin := c.Request.Header.Get("Origin")

		// Allow specific origins (add your frontend URLs)
		allowedOrigins := []string{
			"http://localhost:3000",
			"http://127.0.0.1:3000",
			"https://localhost:3000",
		}

		// Check if origin is allowed
		var allowOrigin string
		for _, allowedOrigin := range allowedOrigins {
			if origin == allowedOrigin {
				allowOrigin = origin
				break
			}
		}

		if allowOrigin == "" && origin != "" {
			// In development, you might want to allow the requesting origin
			// In production, be more restrictive
			allowOrigin = "http://localhost:3000"
		}

		// Set CORS headers
		c.Header("Access-Control-Allow-Origin", allowOrigin)
		
		// CRITICAL: Must be "true" for cookies to work cross-origin
		c.Header("Access-Control-Allow-Credentials", "true")
		
		// Allow necessary headers including CSRF token
		c.Header("Access-Control-Allow-Headers", "Content-Type, Content-Length, Accept-Encoding, X-CSRF-Token, Authorization, Accept, Origin, Cache-Control, X-Requested-With")
		
		// Expose headers that client needs to read
		c.Header("Access-Control-Expose-Headers", "Content-Length, X-CSRF-Token")
		
		c.Header("Access-Control-Allow-Methods", "POST, OPTIONS, GET, PUT, DELETE, PATCH")
		c.Header("Access-Control-Max-Age", "86400")

		if c.Request.Method == "OPTIONS" {
			c.AbortWithStatus(204)
			return
		}

		c.Next()
	})
}