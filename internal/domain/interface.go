package domain

import (
	"context"
	"github.com/google/uuid"
	"golang.org/x/oauth2"
	"time"
)

type UserRepository interface {
	Create(ctx context.Context, user *User) error
	GetByID(ctx context.Context, id uuid.UUID) (*User, error)
	GetByGoogleID(ctx context.Context, googleID string) (*User, error)
	GetByEmail(ctx context.Context, email string) (*User, error)
	Update(ctx context.Context, user *User) error
}

type SessionRepository interface {
	Create(ctx context.Context, session *Session) error
	GetByID(ctx context.Context, sessionID string) (*Session, error)
	GetByRefreshToken(ctx context.Context, refreshToken string) (*Session, error)
	GetByUserID(ctx context.Context, userID uuid.UUID) ([]*Session, error)
	Update(ctx context.Context, session *Session) error
	Delete(ctx context.Context, sessionID string) error
	DeleteByUserID(ctx context.Context, userID uuid.UUID) error
	UpdateLastUsed(ctx context.Context, sessionID string) error

	StoreTemporaryAuth(ctx context.Context, authCode, authData string, expiration time.Duration) error
	GetTemporaryAuth(ctx context.Context, authCode string) (string, error)
}

type OAuthService interface {
	GetAuthURL(state string) string
	ExchangeCode(ctx context.Context, code string) (*oauth2.Token, error)
	GetUserInfo(ctx context.Context, token *oauth2.Token) (*GoogleUserInfo, error)
}

type AuthService interface {
	GenerateTokenPair(userID uuid.UUID, userAgent, ipAddress string) (*TokenPair, error)
	ValidateAccessToken(tokenString string) (uuid.UUID, error)
	RefreshAccessToken(refreshToken string, userAgent, ipAddress string) (*TokenPair, error)
	RevokeSession(sessionID string) error
	GetUserSessions(userID uuid.UUID) ([]*Session, error)
	RevokeAllUserSessions(userID uuid.UUID) error
	// Add these new methods
	StoreTemporaryAuth(authCode string, authResult *AuthResult, expiration time.Duration) error
	ExchangeAuthCode(authCode string) (*AuthResult, error)
}
