package service

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/rs/zerolog/log"
	"googleAuth/internal/config"
	"googleAuth/internal/domain"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

type authenticationService struct {
	config      *config.Config
	oauthSvc    domain.OAuthService
	userRepo    domain.UserRepository
	sessionRepo domain.SessionRepository
	jwtSecret   string
}

type Claims struct {
	UserID    uuid.UUID `json:"user_id"`
	SessionID string    `json:"session_id"`
	TokenType string    `json:"token_type"`
	jwt.RegisteredClaims
}

const (
	AccessTokenDuration  = 1 * time.Hour       // Increased from 15 minutes
	RefreshTokenDuration = 30 * 24 * time.Hour // 30 days
	TempAuthCodeDuration = 5 * time.Minute     // For OAuth flow
)

func NewAuthenticationService(
	cfg *config.Config,
	oauthSvc domain.OAuthService,
	userRepo domain.UserRepository,
	sessionRepo domain.SessionRepository,
) domain.AuthenticationService {
	return &authenticationService{
		config:      cfg,
		oauthSvc:    oauthSvc,
		userRepo:    userRepo,
		sessionRepo: sessionRepo,
		jwtSecret:   cfg.JWTSecret,
	}
}

// OAuth flow methods
func (s *authenticationService) InitiateGoogleAuth(state string) string {
	return s.oauthSvc.GetAuthURL(state)
}

func (s *authenticationService) CompleteGoogleAuth(ctx context.Context, code, state, userAgent, ipAddress string) (*domain.AuthResult, error) {
	// Exchange code for token
	token, err := s.oauthSvc.ExchangeCode(ctx, code)
	if err != nil {
		return nil, fmt.Errorf("failed to exchange code: %w", err)
	}

	// Get user info from Google
	userInfo, err := s.oauthSvc.GetUserInfo(ctx, token)
	if err != nil {
		return nil, fmt.Errorf("failed to get user info: %w", err)
	}

	// Find or create user
	user, err := s.findOrCreateUser(ctx, userInfo)
	if err != nil {
		return nil, fmt.Errorf("failed to find or create user: %w", err)
	}

	// Generate token pair
	tokenPair, err := s.GenerateTokenPair(user.ID, userAgent, ipAddress)
	if err != nil {
		return nil, fmt.Errorf("failed to generate tokens: %w", err)
	}

	return &domain.AuthResult{
		User:   user,
		Tokens: tokenPair,
	}, nil
}

func (s *authenticationService) findOrCreateUser(ctx context.Context, userInfo *domain.GoogleUserInfo) (*domain.User, error) {
	// Try to find existing user
	existingUser, err := s.userRepo.GetByGoogleID(ctx, userInfo.ID)
	if err != nil {
		return nil, err
	}

	if existingUser != nil {
		return existingUser, nil
	}

	// Create new user
	newUser := &domain.User{
		ID:        uuid.New(),
		GoogleID:  userInfo.ID,
		Email:     userInfo.Email,
		Name:      userInfo.Name,
		Picture:   userInfo.Picture,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}

	if err := s.userRepo.Create(ctx, newUser); err != nil {
		return nil, err
	}

	return newUser, nil
}

// Token management methods
func (s *authenticationService) GenerateTokenPair(userID uuid.UUID, userAgent, ipAddress string) (*domain.TokenPair, error) {
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
		ExpiresAt:    time.Now().Add(RefreshTokenDuration),
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

func (s *authenticationService) generateAccessToken(userID uuid.UUID, sessionID string) (string, error) {
	claims := &Claims{
		UserID:    userID,
		SessionID: sessionID,
		TokenType: "access",
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(AccessTokenDuration)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(s.jwtSecret))
}

func (s *authenticationService) generateRefreshToken(userID uuid.UUID, sessionID string) (string, error) {
	claims := &Claims{
		UserID:    userID,
		SessionID: sessionID,
		TokenType: "refresh",
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(RefreshTokenDuration)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(s.jwtSecret))
}

func (s *authenticationService) ValidateAccessToken(tokenString string) (uuid.UUID, error) {
	authInfo, err := s.ValidateAccessTokenWithDetails(tokenString)
	if err != nil {
		return uuid.Nil, err
	}
	return authInfo.UserID, nil
}

func (s *authenticationService) ValidateAccessTokenWithDetails(tokenString string) (*domain.AuthInfo, error) {
	token, err := jwt.ParseWithClaims(tokenString, &Claims{}, func(token *jwt.Token) (interface{}, error) {
		if method, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		} else if method != jwt.SigningMethodHS256 {
			return nil, fmt.Errorf("unexpected HMAC algorithm: %v", method.Alg())
		}
		return []byte(s.jwtSecret), nil
	})

	if err != nil {
		return nil, fmt.Errorf("token parsing failed: %w", err)
	}

	claims, ok := token.Claims.(*Claims)
	if !ok || !token.Valid {
		return nil, fmt.Errorf("invalid token claims")
	}

	if claims.TokenType != "access" {
		return nil, fmt.Errorf("invalid token type: expected access, got %s", claims.TokenType)
	}

	if claims.UserID == uuid.Nil {
		return nil, fmt.Errorf("invalid user ID in token")
	}

	// Verify session still exists and is valid
	session, err := s.sessionRepo.GetByID(context.Background(), claims.SessionID)
	if err != nil {
		return nil, fmt.Errorf("session verification failed: %w", err)
	}

	if session == nil {
		return nil, fmt.Errorf("session not found")
	}

	if time.Now().After(session.ExpiresAt) {
		// Clean up expired session asynchronously
		go s.sessionRepo.Delete(context.Background(), session.ID)
		return nil, fmt.Errorf("session expired")
	}

	// Update last used time asynchronously
	go s.sessionRepo.UpdateLastUsed(context.Background(), claims.SessionID)

	return &domain.AuthInfo{
		UserID:    claims.UserID,
		SessionID: claims.SessionID,
	}, nil
}

func (s *authenticationService) RefreshAccessToken(refreshToken, userAgent, ipAddress string) (*domain.TokenPair, error) {
	if refreshToken == "" {
		return nil, fmt.Errorf("refresh token is required")
	}

	token, err := jwt.ParseWithClaims(refreshToken, &Claims{}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(s.jwtSecret), nil
	})

	if err != nil {
		return nil, fmt.Errorf("invalid refresh token: %w", err)
	}

	claims, ok := token.Claims.(*Claims)
	if !ok || !token.Valid {
		return nil, fmt.Errorf("invalid refresh token claims")
	}

	if claims.TokenType != "refresh" {
		return nil, fmt.Errorf("invalid token type: expected refresh, got %s", claims.TokenType)
	}

	session, err := s.sessionRepo.GetByRefreshToken(context.Background(), refreshToken)
	if err != nil {
		log.Printf("DEBUG: Error getting session by refresh token: %v", err)
		return nil, fmt.Errorf("database error: %w", err)
	}

	if session == nil {
		log.Printf("DEBUG: Session not found for refresh token")
		return nil, fmt.Errorf("invalid refresh token: session not found")
	}

	if time.Now().After(session.ExpiresAt) {
		// Clean up expired session
		go s.sessionRepo.Delete(context.Background(), session.ID)

		return nil, fmt.Errorf("refresh token expired")
	}

	// Generate new token pair
	newTokenPair, err := s.GenerateTokenPair(session.UserID, userAgent, ipAddress)
	if err != nil {
		log.Printf("Degubing: Error generating new token pair")
		return nil, fmt.Errorf("failed to generate new tokens: %w", err)
	}

	if err := s.sessionRepo.Delete(context.Background(), session.ID); err != nil {
		log.Printf("Debug: warn - failed to delete old session: %v", err)
	}

	log.Printf("Generated new tokens with session Id: %s", newTokenPair)
	return newTokenPair, nil
}

// Session management methods
func (s *authenticationService) RevokeSession(sessionID string) error {
	return s.sessionRepo.Delete(context.Background(), sessionID)
}

func (s *authenticationService) GetUserSessions(userID uuid.UUID) ([]*domain.Session, error) {
	return s.sessionRepo.GetByUserID(context.Background(), userID)
}

func (s *authenticationService) RevokeAllUserSessions(userID uuid.UUID) error {
	return s.sessionRepo.DeleteByUserID(context.Background(), userID)
}

// Temporary auth code methods
func (s *authenticationService) StoreTemporaryAuth(authCode string, authResult *domain.AuthResult, expiration time.Duration) error {
	if authCode == "" {
		return fmt.Errorf("auth code is required")
	}

	if authResult == nil {
		return fmt.Errorf("auth result is required")
	}

	authResultJSON, err := json.Marshal(authResult)
	if err != nil {
		return err
	}

	return s.sessionRepo.StoreTemporaryAuth(context.Background(), authCode, string(authResultJSON), expiration)
}

func (s *authenticationService) ExchangeAuthCode(authCode string) (*domain.AuthResult, error) {
	if authCode == "" {
		return nil, fmt.Errorf("auth code is required")
	}

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
