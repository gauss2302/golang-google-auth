package config

import (
	"crypto/rand"
	"encoding/base64"
	"log"
	"os"
	"strconv"
	"time"

	"github.com/joho/godotenv"
)

type Config struct {
	Environment        string
	Port               string
	DatabaseURL        string
	RedisURL           string
	JWTSecret          string
	GoogleClientID     string
	GoogleClientSecret string
	GoogleRedirectURL  string
	FrontendURL        string

	// Security Settings
	CSRFKey            []byte
	RateLimitPerMinute int
	RateLimitInterval  time.Duration
	CookieSecure       bool
}

func Load() *Config {
	if err := godotenv.Load(".env"); err != nil {
		log.Println("No .env file found")
	}

	cfg := &Config{
		Environment:        getEnv("ENVIRONMENT", "development"),
		Port:               getEnv("PORT", "8080"),
		DatabaseURL:        getEnv("DATABASE_URL", ""),
		RedisURL:           getEnv("REDIS_URL", "redis://localhost:6379/0"),
		JWTSecret:          getEnv("JWT_SECRET", ""),
		GoogleClientID:     getEnv("GOOGLE_CLIENT_ID", ""),
		GoogleClientSecret: getEnv("GOOGLE_CLIENT_SECRET", ""),
		GoogleRedirectURL:  getEnv("GOOGLE_REDIRECT_URL", ""),
		FrontendURL:        getEnv("FRONTEND_URL", "http://localhost:3000"),

		// Security defaults
		RateLimitPerMinute: getEnvAsInt("RATE_LIMIT_PER_MINUTE", 100),
		RateLimitInterval:  time.Duration(getEnvAsInt("RATE_LIMIT_INTERVAL_SECONDS", 60)) * time.Second,
		CookieSecure:       getEnvAsBool("COOKIE_SECURE", true),
	}

	// Generate or load CSRF key
	if csrfKey := getEnv("CSRF_KEY", ""); csrfKey != "" {
		decoded, err := base64.StdEncoding.DecodeString(csrfKey)
		if err != nil {
			log.Fatal("Invalid CSRF_KEY format, must be base64 encoded")
		}
		cfg.CSRFKey = decoded
	} else {
		// Generate a random CSRF key for development
		cfg.CSRFKey = generateRandomKey(32)
		log.Println("Generated random CSRF key for development. Set CSRF_KEY in production!")
	}

	return cfg
}

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

func getEnvAsInt(key string, defaultValue int) int {
	if value := os.Getenv(key); value != "" {
		if intValue, err := strconv.Atoi(value); err == nil {
			return intValue
		}
	}
	return defaultValue
}

func getEnvAsBool(key string, defaultValue bool) bool {
	if value := os.Getenv(key); value != "" {
		if boolValue, err := strconv.ParseBool(value); err == nil {
			return boolValue
		}
	}
	return defaultValue
}

func generateRandomKey(length int) []byte {
	key := make([]byte, length)
	if _, err := rand.Read(key); err != nil {
		log.Fatal("Failed to generate random key:", err)
	}
	return key
}
