package service

import (
	"context"
	"encoding/json"
	"fmt"
	"googleAuth/internal/config"
	"googleAuth/internal/domain"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

type authService struct {
	jwtSecret   string
	userRepo    domain.UserRepository
	sessionRepo domain.SessionRepository
}

type Claims struct {
	UserID    uuid.UUID `json:"user_id"`
	SessionID string    `json:"session_id"`
	jwt.RegisteredClaims
}

func NewAuthService(cfg *config.Config, userRepo domain.UserRepository, sessionRepo domain.SessionRepository) domain.AuthService {
	return &authService{
		jwtSecret:   cfg.JWTSecret,
		userRepo:    userRepo,
		sessionRepo: sessionRepo,
	}
}

// internal/service/auth_service.go - Add these methods
func (s *authService) StoreTemporaryAuth(authCode string, authResult *domain.AuthResult, expiration time.Duration) error {
	authResultJSON, err := json.Marshal(authResult)
	if err != nil {
		return err
	}

	return s.sessionRepo.StoreTemporaryAuth(context.Background(), authCode, string(authResultJSON), expiration)
}

func (s *authService) ExchangeAuthCode(authCode string) (*domain.AuthResult, error) {
	authData, err := s.sessionRepo.GetTemporaryAuth(context.Background(), authCode)
	if err != nil {
		return nil, err
	}

	if authData == "" {
		return nil, fmt.Errorf("invalid or expired auth code")
	}

	var authResult domain.AuthResult
	if err := json.Unmarshal([]byte(authData), &authResult); err != nil {
		return nil, err
	}

	return &authResult, nil
}

func (s *authService) GenerateTokenPair(userID uuid.UUID, userAgent, ipAddress string) (*domain.TokenPair, error) {
	sessionID := uuid.New().String()

	accessToken, err := s.generateAccessToken(userID, sessionID)
	if err != nil {
		return nil, err
	}

	refreshToken, err := s.generateRefreshToken(userID, sessionID)
	if err != nil {
		return nil, err
	}

	session := &domain.Session{
		ID:           sessionID,
		UserID:       userID,
		RefreshToken: refreshToken,
		ExpiresAt:    time.Now().Add(24 * 7 * time.Hour), // 7 days
		CreatedAt:    time.Now(),
		LastUsedAt:   time.Now(),
		UserAgent:    userAgent,
		IPAddress:    ipAddress,
	}

	if err := s.sessionRepo.Create(context.Background(), session); err != nil {
		return nil, err
	}

	return &domain.TokenPair{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		SessionID:    sessionID,
	}, nil
}

func (s *authService) generateAccessToken(userID uuid.UUID, sessionID string) (string, error) {
	claims := &Claims{
		UserID:    userID,
		SessionID: sessionID,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(15 * time.Minute)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(s.jwtSecret))
}

func (s *authService) generateRefreshToken(userID uuid.UUID, sessionID string) (string, error) {
	claims := &Claims{
		UserID:    userID,
		SessionID: sessionID,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(24 * 7 * time.Hour)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(s.jwtSecret))
}

func (s *authService) ValidateAccessToken(tokenString string) (uuid.UUID, error) {
	token, err := jwt.ParseWithClaims(tokenString, &Claims{}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(s.jwtSecret), nil
	})

	if err != nil {
		return uuid.Nil, err
	}

	if claims, ok := token.Claims.(*Claims); ok && token.Valid {
		// Verify session still exists
		session, err := s.sessionRepo.GetByID(context.Background(), claims.SessionID)
		if err != nil || session == nil {
			return uuid.Nil, fmt.Errorf("session not found or expired")
		}

		// Update last used time asynchronously
		go s.sessionRepo.UpdateLastUsed(context.Background(), claims.SessionID)

		return claims.UserID, nil
	}

	return uuid.Nil, fmt.Errorf("invalid token")
}

func (s *authService) RefreshAccessToken(refreshToken string, userAgent, ipAddress string) (*domain.TokenPair, error) {
	session, err := s.sessionRepo.GetByRefreshToken(context.Background(), refreshToken)
	if err != nil || session == nil {
		return nil, fmt.Errorf("invalid refresh token")
	}

	if time.Now().After(session.ExpiresAt) {
		// Clean up expired session
		s.sessionRepo.Delete(context.Background(), session.ID)
		return nil, fmt.Errorf("refresh token expired")
	}

	// Generate new token pair
	return s.GenerateTokenPair(session.UserID, userAgent, ipAddress)
}

func (s *authService) RevokeSession(sessionID string) error {
	return s.sessionRepo.Delete(context.Background(), sessionID)
}

func (s *authService) GetUserSessions(userID uuid.UUID) ([]*domain.Session, error) {
	return s.sessionRepo.GetByUserID(context.Background(), userID)
}

func (s *authService) RevokeAllUserSessions(userID uuid.UUID) error {
	return s.sessionRepo.DeleteByUserID(context.Background(), userID)
}
