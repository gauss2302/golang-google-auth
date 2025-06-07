package security

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/redis/go-redis/v9"
	"github.com/rs/zerolog/log"
)

const (
	DefaultRateLimit    = 100
	DefaultRateInterval = time.Minute
)

var ErrRateLimitExceeded = errors.New("rate limit exceeded")

type RateLimiterConfig struct {
	Redis              *redis.Client
	Limit              int
	Interval           time.Duration
	SkipSuccessfulAuth bool
}

type RateLimiter struct {
	redis    *redis.Client
	limit    int
	interval time.Duration
	skipAuth bool
}

func NewRateLimiter(config RateLimiterConfig) *RateLimiter {
	if config.Redis == nil {
		panic("Redis client is required for rate limiting")
	}

	if config.Limit <= 0 {
		config.Limit = DefaultRateLimit
	}
	if config.Interval <= 0 {
		config.Interval = DefaultRateInterval
	}
	return &RateLimiter{
		redis:    config.Redis,
		limit:    config.Limit,
		interval: config.Interval,
		skipAuth: config.SkipSuccessfulAuth,
	}
}

// Gin middleware for rate limiting
func (rl *RateLimiter) GinMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		if c.Request.Method == http.MethodOptions {
			c.Next()
			return
		}

		count, err := rl.CheckRateLimit(c.Request.Context(), c.Request)
		if err != nil {
			if errors.Is(err, ErrRateLimitExceeded) {
				c.Header("X-RateLimit-Limit", strconv.Itoa(rl.limit))
				c.Header("X-RateLimit-Remaining", "0")
				c.Header("X-RateLimit-Reset", strconv.FormatInt(time.Now().Add(rl.interval).Unix(), 10))
				c.Header("Retry-After", strconv.Itoa(int(rl.interval.Seconds())))
				c.JSON(http.StatusTooManyRequests, gin.H{"error": "Rate limit exceeded"})
				c.Abort()
				return
			}

			log.Error().Err(err).Msg("Rate limiting error")
		}

		c.Header("X-RateLimit-Limit", strconv.Itoa(rl.limit))
		c.Header("X-RateLimit-Remaining", strconv.Itoa(rl.limit-count))
		c.Header("X-RateLimit-Reset", strconv.FormatInt(time.Now().Add(rl.interval).Unix(), 10))

		c.Next()
	}
}

// Standard HTTP middleware for rate limiting
func (rl *RateLimiter) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodOptions {
			next.ServeHTTP(w, r)
			return
		}

		count, err := rl.CheckRateLimit(r.Context(), r)
		if err != nil {
			if errors.Is(err, ErrRateLimitExceeded) {
				w.Header().Set("X-RateLimit-Limit", strconv.Itoa(rl.limit))
				w.Header().Set("X-RateLimit-Remaining", "0")
				w.Header().Set("X-RateLimit-Reset", strconv.FormatInt(time.Now().Add(rl.interval).Unix(), 10))
				w.Header().Set("Retry-After", strconv.Itoa(int(rl.interval.Seconds())))
				http.Error(w, "Rate limit exceeded", http.StatusTooManyRequests)
				return
			}

			log.Error().Err(err).Msg("Rate limiting error")
		}

		w.Header().Set("X-RateLimit-Limit", strconv.Itoa(rl.limit))
		w.Header().Set("X-RateLimit-Remaining", strconv.Itoa(rl.limit-count))
		w.Header().Set("X-RateLimit-Reset", strconv.FormatInt(time.Now().Add(rl.interval).Unix(), 10))

		next.ServeHTTP(w, r)
	})
}

func getIPAddress(r *http.Request) string {
	// Check X-Forwarded-For header
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		ips := strings.Split(xff, ",")
		if len(ips) > 0 {
			clientIP := strings.TrimSpace(ips[0])
			return clientIP
		}
	}

	// Check X-Real-IP header
	if xrip := r.Header.Get("X-Real-IP"); xrip != "" {
		return xrip
	}

	// Fall back to RemoteAddr
	ip, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return ip
}

func (rl *RateLimiter) getLimitKey(r *http.Request) string {
	ip := getIPAddress(r)
	path := r.URL.Path
	return fmt.Sprintf("ratelimit:%s:%s", ip, path)
}

func (rl *RateLimiter) CheckRateLimit(ctx context.Context, r *http.Request) (int, error) {
	key := rl.getLimitKey(r)
	now := time.Now().Unix()
	windowStart := now - int64(rl.interval.Seconds())

	// Remove old entries (outside the current window)
	err := rl.redis.ZRemRangeByScore(ctx, key, "0", strconv.FormatInt(windowStart, 10)).Err()
	if err != nil {
		log.Error().Err(err).Msg("Failed to remove old rate limit entries")
		// Allow the request to proceed if we can't communicate with Redis
		return 0, nil
	}

	// Count existing requests in the current window
	count, err := rl.redis.ZCard(ctx, key).Result()
	if err != nil {
		log.Error().Err(err).Msg("Failed to count rate limit entries")
		// Allow the request to proceed if we can't communicate with Redis
		return 0, nil
	}

	// Check if the rate limit has been exceeded
	if count >= int64(rl.limit) {
		return int(count), ErrRateLimitExceeded
	}

	// Add the current request to the sorted set with the current timestamp as score
	err = rl.redis.ZAdd(ctx, key, redis.Z{
		Score:  float64(now),
		Member: now,
	}).Err()
	if err != nil {
		log.Error().Err(err).Msg("Failed to add rate limit entry")
	}

	// Set expiration for the key to the rate limit interval + 1 minute
	err = rl.redis.Expire(ctx, key, rl.interval+time.Minute).Err()
	if err != nil {
		log.Error().Err(err).Msg("Failed to set rate limit key expiration")
	}

	return int(count) + 1, nil
}
