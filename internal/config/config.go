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
		log.Println("No .env file found, using system environment variables")
	}

	cfg := &Config{
		Environment:        getRequiredEnv("ENVIRONMENT"),
		Port:               getRequiredEnv("PORT"),
		DatabaseURL:        getRequiredEnv("DATABASE_URL"),
		RedisURL:           getRequiredEnv("REDIS_URL"),
		JWTSecret:          getRequiredEnv("JWT_SECRET"),
		GoogleClientID:     getRequiredEnv("GOOGLE_CLIENT_ID"),
		GoogleClientSecret: getRequiredEnv("GOOGLE_CLIENT_SECRET"),
		GoogleRedirectURL:  getRequiredEnv("GOOGLE_REDIRECT_URL"),
		FrontendURL:        getRequiredEnv("FRONTEND_URL"),

		RateLimitPerMinute: getRequiredEnvAsInt("RATE_LIMIT_PER_MINUTE"),
		RateLimitInterval:  time.Duration(getRequiredEnvAsInt("RATE_LIMIT_INTERVAL_SECONDS")) * time.Second,
		CookieSecure:       getRequiredEnvAsBool("COOKIE_SECURE"),
	}

	// Handle CSRF key
	csrfKey := getRequiredEnv("CSRF_KEY")
	if csrfKey == "GENERATE" {
		cfg.CSRFKey = generateRandomKey(32)
		log.Println("Generated random CSRF key for development. Set CSRF_KEY in production!")
	} else {
		decoded, err := base64.StdEncoding.DecodeString(csrfKey)
		if err != nil {
			log.Fatal("Invalid CSRF_KEY format, must be base64 encoded")
		}
		cfg.CSRFKey = decoded
	}

	return cfg
}

func getRequiredEnv(key string) string {
	value := os.Getenv(key)
	if value == "" {
		log.Fatalf("Required environment variable %s is not set", key)
	}
	return value
}

func getRequiredEnvAsInt(key string) int {
	value := getRequiredEnv(key)
	intValue, err := strconv.Atoi(value)
	if err != nil {
		log.Fatalf("Environment variable %s must be a valid integer, got: %s", key, value)
	}
	return intValue
}

func getRequiredEnvAsBool(key string) bool {
	value := getRequiredEnv(key)
	boolValue, err := strconv.ParseBool(value)
	if err != nil {
		log.Fatalf("Environment variable %s must be a valid boolean, got: %s", key, value)
	}
	return boolValue
}

func generateRandomKey(length int) []byte {
	key := make([]byte, length)
	if _, err := rand.Read(key); err != nil {
		log.Fatal("Failed to generate random key:", err)
	}
	return key
}
