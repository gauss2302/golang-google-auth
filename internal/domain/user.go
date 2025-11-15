package domain

import (
	"time"

	"github.com/google/uuid"
)

type User struct {
	ID             uuid.UUID `json:"id" db:"id"`
	GoogleID       string    `json:"google_id" db:"google_id"`
	TwitterID      string    `json:"twitter_id" db:"twitter_id"`
	TwitterHandle  string    `json:"twitter_handle" db:"twitter_handle"`
	Email          string    `json:"email" db:"email"`
	HashedPassword string    `json:"hashed_password" db:"hashed_password"`
	Name           string    `json:"name" db:"name"`
	FirstName      string    `json:"first_name" db:"first_name"`
	LastName       string    `json:"last_name" db:"last_name"`
	Picture        string    `json:"picture" db:"picture"`
	CreatedAt      time.Time `json:"created_at" db:"created_at"`
	UpdatedAt      time.Time `json:"updated_at" db:"updated_at"`
}

type GoogleUserInfo struct {
	ID      string `json:"id"`
	Email   string `json:"email"`
	Name    string `json:"name"`
	Picture string `json:"picture"`
}

type TwitterUserInfo struct {
	ID              string `json:"id"`
	Name            string `json:"name"`
	Username        string `json:"username"`
	Email           string `json:"email"`
	ProfileImageURL string `json:"profile_image_url"`
}

type TokenPair struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	SessionID    string `json:"session_id"`
}

type Session struct {
	ID           string    `json:"id"`
	UserID       uuid.UUID `json:"user_id"`
	RefreshToken string    `json:"refresh_token"`
	ExpiresAt    time.Time `json:"expires_at"`
	CreatedAt    time.Time `json:"created_at"`
	LastUsedAt   time.Time `json:"last_used_at"`
	UserAgent    string    `json:"user_agent"`
	IPAddress    string    `json:"ip_address"`
}

type AuthResult struct {
	User   *User      `json:"user"`
	Tokens *TokenPair `json:"tokens"`
}

// AuthInfo contains detailed information about authenticated user
type AuthInfo struct {
	UserID    uuid.UUID `json:"user_id"`
	SessionID string    `json:"session_id"`
}
