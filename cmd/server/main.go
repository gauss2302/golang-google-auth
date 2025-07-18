package main

import (
	"context"
	"errors"
	"googleAuth/internal/config"
	"googleAuth/internal/handler"
	"googleAuth/internal/middleware"
	"googleAuth/internal/repository"
	"googleAuth/internal/security"
	"googleAuth/internal/service"
	"googleAuth/pkg/database"
	"googleAuth/pkg/redis"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/gin-gonic/gin"
)

func main() {
	cfg := config.Load()

	db, err := database.NewPostgresConnection(cfg.DatabaseURL)
	if err != nil {
		log.Fatal("Failed to connect to database:", err)
	}
	defer db.Close()

	if err := database.RunMigrations(cfg.DatabaseURL); err != nil {
		log.Fatal("Failed to run migrations:", err)
	}

	redisClient, err := redis.NewRedisClient(cfg.RedisURL)
	if err != nil {
		log.Fatal("Failed to connect to Redis:", err)
	}
	defer redisClient.Close()

	// Initialize security components using the constructor functions
	rateLimiter := security.NewRateLimiter(security.RateLimiterConfig{
		Redis:              redisClient,
		Limit:              cfg.RateLimitPerMinute,
		Interval:           cfg.RateLimitInterval,
		SkipSuccessfulAuth: false,
	})

	csrfProtection := security.NewCSRFProtection(security.CSRFConfig{
		Key:            cfg.CSRFKey,
		CookieSecure:   cfg.CookieSecure,
		CookiePath:     "/",
		CookieDomain:   "",
		CookieMaxAge:   86400, // 24 hours
		CookieSameSite: http.SameSiteStrictMode,
	})

	userRepo := repository.NewUserRepository(db)
	sessionRepo := repository.NewSessionRepository(redisClient)
	oauthService := service.NewOAuthService(cfg, userRepo)
	authService := service.NewAuthService(cfg, userRepo, sessionRepo)

	authHandler := handler.NewAuthHandler(oauthService, authService, userRepo, cfg)
	userHandler := handler.NewUserHandler(userRepo)

	router := setupRouter(cfg, authHandler, userHandler, rateLimiter, csrfProtection)

	srv := &http.Server{
		Addr:    ":" + cfg.Port,
		Handler: router,
	}

	go func() {
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Fatalf("Server startup failed: %s\n", err)
		}
	}()

	log.Printf("Server started on port %s with security features enabled", cfg.Port)
	log.Printf("Rate limiting: %d requests per %v", cfg.RateLimitPerMinute, cfg.RateLimitInterval)
	log.Printf("CSRF protection: enabled with secure cookies=%v", cfg.CookieSecure)

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	log.Println("Shutting down server...")

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := srv.Shutdown(ctx); err != nil {
		log.Fatal("Server forced to shutdown:", err)
	}

	log.Println("Server exited")
}

func setupRouter(cfg *config.Config, authHandler *handler.AuthHandler, userHandler *handler.UserHandler, rateLimiter *security.RateLimiter, csrfProtection *security.CSRFProtection) *gin.Engine {
	if cfg.Environment == "production" {
		gin.SetMode(gin.ReleaseMode)
	}

	router := gin.New()
	router.Use(gin.Logger())
	router.Use(gin.Recovery())
	router.Use(middleware.CORS())

	// Apply rate limiting to all routes using the created instance
	router.Use(rateLimiter.GinMiddleware())

	api := router.Group("/api/v1")
	{
		// Health check endpoint (no security needed)
		api.GET("/health", func(c *gin.Context) {
			c.JSON(http.StatusOK, gin.H{
				"status":    "healthy",
				"timestamp": time.Now().Unix(),
			})
		})

		// CSRF token endpoint using the created instance
		api.GET("/csrf-token", csrfProtection.GinMiddleware(), func(c *gin.Context) {
			token := security.GetCSRFToken(c)
			c.JSON(http.StatusOK, gin.H{"csrf_token": token})
		})

		auth := api.Group("/auth")
		{
			// OAuth endpoints (CSRF protection for callback)
			auth.GET("/google", authHandler.GoogleAuth)
			auth.GET("/google/callback", csrfProtection.GinMiddleware(), authHandler.GoogleCallback)

			// Token management (requires CSRF protection)
			auth.POST("/refresh", csrfProtection.GinMiddleware(), authHandler.RefreshToken)
			auth.POST("/logout", csrfProtection.GinMiddleware(), middleware.AuthMiddleware(cfg.JWTSecret), authHandler.Logout)
			auth.POST("/exchange-code", csrfProtection.GinMiddleware(), authHandler.ExchangeAuthCode)

			// Session management (requires auth + CSRF)
			auth.GET("/sessions", middleware.AuthMiddleware(cfg.JWTSecret), authHandler.GetSessions)
			auth.DELETE("/sessions/:sessionId", csrfProtection.GinMiddleware(), middleware.AuthMiddleware(cfg.JWTSecret), authHandler.RevokeSession)
			auth.DELETE("/sessions", csrfProtection.GinMiddleware(), middleware.AuthMiddleware(cfg.JWTSecret), authHandler.RevokeAllSessions)
		}

		protected := api.Group("/")
		protected.Use(middleware.AuthMiddleware(cfg.JWTSecret))
		{
			// Profile endpoints (GET is safe, PUT requires CSRF)
			protected.GET("/profile", userHandler.GetProfile)
			protected.PUT("/profile", csrfProtection.GinMiddleware(), userHandler.UpdateProfile)
		}
	}

	return router
}
