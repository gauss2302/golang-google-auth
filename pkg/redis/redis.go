package redis

import (
	"context"
	"crypto/tls"
	"github.com/redis/go-redis/v9"
	"net/url"
	"strconv"
)

func NewRedisClient(redisURL string) (*redis.Client, error) {
	opts, err := parseRedisURL(redisURL)
	if err != nil {
		return nil, err
	}

	client := redis.NewClient(opts)

	ctx := context.Background()
	if err := client.Ping(ctx).Err(); err != nil {
		return nil, err
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
