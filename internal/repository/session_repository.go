package repository

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/redis/go-redis/v9"
	"googleAuth/internal/domain"
	"time"

	"github.com/google/uuid"
)

type sessionRepository struct {
	client *redis.Client
}

func NewSessionRepository(client *redis.Client) domain.SessionRepository {
	return &sessionRepository{client: client}
}

func (r *sessionRepository) Create(ctx context.Context, session *domain.Session) error {
	sessionKey := fmt.Sprintf("session:%s", session.ID)
	refreshTokenKey := fmt.Sprintf("refresh_token:%s", session.RefreshToken)
	userSessionsKey := fmt.Sprintf("user_sessions:%s", session.UserID.String())

	pipe := r.client.Pipeline()

	sessionData, err := json.Marshal(session)
	if err != nil {
		return err
	}

	// Store session data
	pipe.Set(ctx, sessionKey, sessionData, time.Until(session.ExpiresAt))

	// Store refresh token mapping to session ID
	pipe.Set(ctx, refreshTokenKey, session.ID, time.Until(session.ExpiresAt))

	// Add session to user's sessions set
	pipe.SAdd(ctx, userSessionsKey, session.ID)
	pipe.Expire(ctx, userSessionsKey, 24*7*time.Hour) // Expire user sessions key after 7 days

	_, err = pipe.Exec(ctx)
	return err
}

func (r *sessionRepository) GetByID(ctx context.Context, sessionID string) (*domain.Session, error) {
	sessionKey := fmt.Sprintf("session:%s", sessionID)

	data, err := r.client.Get(ctx, sessionKey).Result()
	if err == redis.Nil {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	var session domain.Session
	if err := json.Unmarshal([]byte(data), &session); err != nil {
		return nil, err
	}

	return &session, nil
}

func (r *sessionRepository) GetByRefreshToken(ctx context.Context, refreshToken string) (*domain.Session, error) {
	refreshTokenKey := fmt.Sprintf("refresh_token:%s", refreshToken)

	sessionID, err := r.client.Get(ctx, refreshTokenKey).Result()
	if err == redis.Nil {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	return r.GetByID(ctx, sessionID)
}

func (r *sessionRepository) GetByUserID(ctx context.Context, userID uuid.UUID) ([]*domain.Session, error) {
	userSessionsKey := fmt.Sprintf("user_sessions:%s", userID.String())

	sessionIDs, err := r.client.SMembers(ctx, userSessionsKey).Result()
	if err != nil {
		return nil, err
	}

	var sessions []*domain.Session
	for _, sessionID := range sessionIDs {
		session, err := r.GetByID(ctx, sessionID)
		if err != nil {
			continue // Skip invalid sessions
		}
		if session != nil {
			sessions = append(sessions, session)
		}
	}

	return sessions, nil
}

func (r *sessionRepository) Update(ctx context.Context, session *domain.Session) error {
	sessionKey := fmt.Sprintf("session:%s", session.ID)

	sessionData, err := json.Marshal(session)
	if err != nil {
		return err
	}

	return r.client.Set(ctx, sessionKey, sessionData, time.Until(session.ExpiresAt)).Err()
}

func (r *sessionRepository) Delete(ctx context.Context, sessionID string) error {
	session, err := r.GetByID(ctx, sessionID)
	if err != nil || session == nil {
		return err
	}

	sessionKey := fmt.Sprintf("session:%s", sessionID)
	refreshTokenKey := fmt.Sprintf("refresh_token:%s", session.RefreshToken)
	userSessionsKey := fmt.Sprintf("user_sessions:%s", session.UserID.String())

	pipe := r.client.Pipeline()
	pipe.Del(ctx, sessionKey)
	pipe.Del(ctx, refreshTokenKey)
	pipe.SRem(ctx, userSessionsKey, sessionID)

	_, err = pipe.Exec(ctx)
	return err
}

func (r *sessionRepository) DeleteByUserID(ctx context.Context, userID uuid.UUID) error {
	sessions, err := r.GetByUserID(ctx, userID)
	if err != nil {
		return err
	}

	if len(sessions) == 0 {
		return nil
	}

	pipe := r.client.Pipeline()
	userSessionsKey := fmt.Sprintf("user_sessions:%s", userID.String())

	for _, session := range sessions {
		sessionKey := fmt.Sprintf("session:%s", session.ID)
		refreshTokenKey := fmt.Sprintf("refresh_token:%s", session.RefreshToken)

		pipe.Del(ctx, sessionKey)
		pipe.Del(ctx, refreshTokenKey)
	}

	pipe.Del(ctx, userSessionsKey)

	_, err = pipe.Exec(ctx)
	return err
}

func (r *sessionRepository) UpdateLastUsed(ctx context.Context, sessionID string) error {
	session, err := r.GetByID(ctx, sessionID)
	if err != nil || session == nil {
		return err
	}

	session.LastUsedAt = time.Now()
	return r.Update(ctx, session)
}
