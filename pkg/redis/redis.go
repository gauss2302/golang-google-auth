package redis

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/url"
	"strconv"
	"time"

	"github.com/redis/go-redis/v9"
)

func NewRedisClient(redisURL string) (*redis.Client, error) {
	opts, err := parseRedisURL(redisURL)
	if err != nil {
		return nil, fmt.Errorf("failed to parse Redis URL: %w", err)
	}

	// Добавляем таймауты для продакшена
	opts.DialTimeout = 5 * time.Second
	opts.ReadTimeout = 3 * time.Second
	opts.WriteTimeout = 3 * time.Second
	opts.PoolTimeout = 4 * time.Second

	client := redis.NewClient(opts)

	// Проверяем подключение с таймаутом
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := client.Ping(ctx).Err(); err != nil {
		return nil, fmt.Errorf("failed to connect to Redis: %w", err)
	}

	return client, nil
}

func parseRedisURL(redisURL string) (*redis.Options, error) {
	u, err := url.Parse(redisURL)
	if err != nil {
		return nil, err
	}

	opts := &redis.Options{
		Addr: u.Host,
	}

	if u.User != nil {
		if password, ok := u.User.Password(); ok {
			opts.Password = password
		}
		if u.User.Username() != "" {
			opts.Username = u.User.Username()
		}
	}

	if u.Path != "" && u.Path != "/" {
		if db, err := strconv.Atoi(u.Path[1:]); err == nil {
			opts.DB = db
		}
	}

	// Enable TLS for secure connections
	if u.Scheme == "rediss" {
		opts.TLSConfig = &tls.Config{
			ServerName: u.Hostname(),
		}
	}

	return opts, nil
}
