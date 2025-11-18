package domain

import (
	"context"
	"time"

	"github.com/google/uuid"
	"golang.org/x/oauth2"
)

type UserRepository interface {
	Create(ctx context.Context, user *User) error
	GetByID(ctx context.Context, id uuid.UUID) (*User, error)
	GetByGoogleID(ctx context.Context, googleID string) (*User, error)
	GetByTwitterID(ctx context.Context, twitterID string) (*User, error)
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
	BlacklistToken(ctx context.Context, jti string, expiresAt time.Time) error
	IsTokenBlacklisted(ctx context.Context, jti string) (bool, error)
}

type OAuthService interface {
	GetAuthURL(state string) string
	ExchangeCode(ctx context.Context, code string) (*oauth2.Token, error)
	GetUserInfo(ctx context.Context, token *oauth2.Token) (*GoogleUserInfo, error)
	ValidateGoogleIDToken(ctx context.Context, idToken string) (*GoogleUserInfo, error)
}

type TwitterOAuthService interface {
	GetAuthURL(state string) string
	ExchangeCode(ctx context.Context, code string) (*oauth2.Token, error)
	GetUserInfo(ctx context.Context, token *oauth2.Token) (*TwitterUserInfo, error)
}

type AuthenticationService interface {
	// OAuth flow
	InitiateGoogleAuth(state string) string
	CompleteGoogleAuth(ctx context.Context, code, state, userAgent, ipAddress string) (*AuthResult, error)
	InitiateTwitterAuth(state string) string
	CompleteTwitterAuth(ctx context.Context, code, state, userAgent, ipAddress string) (*AuthResult, error)
	AuthenticateWithGoogleIDToken(ctx context.Context, idToken, userAgent, ipAddress string) (*AuthResult, error)

	// Token management
	GenerateTokenPair(userID uuid.UUID, userAgent, ipAddress string) (*TokenPair, error)
	//ValidateAccessToken(tokenString string) (uuid.UUID, error)
	ValidateAccessTokenWithDetails(ctx context.Context, tokenString string) (*AuthInfo, error)
	RefreshAccessToken(ctx context.Context, refreshToken, userAgent, ipAddress string) (*TokenPair, error)

	// Session management
	RevokeSession(sessionID string) error
	GetUserSessions(userID uuid.UUID) ([]*Session, error)
	RevokeAllUserSessions(userID uuid.UUID) error

	// Temporary auth codes for frontend callback
	StoreTemporaryAuth(authCode string, authResult *AuthResult, expiration time.Duration) error
	ExchangeAuthCode(authCode string) (*AuthResult, error)
}
