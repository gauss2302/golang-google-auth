package service

import (
	"context"
	"encoding/json"
	"fmt"
	"googleAuth/internal/config"
	"googleAuth/internal/domain"
	"net/http"
	"sort"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
)

type authenticationService struct {
	config          *config.Config
	oauthSvc        domain.OAuthService
	twitterOAuthSvc domain.TwitterOAuthService
	userRepo        domain.UserRepository
	sessionRepo     domain.SessionRepository
	jwtSecret       string
}

type Claims struct {
	UserID    uuid.UUID `json:"user_id"`
	SessionID string    `json:"session_id"`
	TokenType string    `json:"token_type"`
	JTI       string    `json:"jti"`
	jwt.RegisteredClaims
}

const (
	AccessTokenDuration  = 1 * time.Hour
	RefreshTokenDuration = 30 * 24 * time.Hour
	TempAuthCodeDuration = 5 * time.Minute
	maxActiveSessions    = 10
)

type CookieConfig struct {
	Name     string
	Path     string
	Domain   string
	MaxAge   int
	HttpOnly bool
	Secure   bool
	SameSite http.SameSite
}

func DefaultCookieConfig() *CookieConfig {
	return &CookieConfig{
		Name:     "refresh_token",
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   int(RefreshTokenDuration.Seconds()),
	}
}

func NewAuthenticationService(
	cfg *config.Config,
	oauthSvc domain.OAuthService,
	twitterOAuthSvc domain.TwitterOAuthService,
	userRepo domain.UserRepository,
	sessionRepo domain.SessionRepository,
) domain.AuthenticationService {
	return &authenticationService{
		config:          cfg,
		oauthSvc:        oauthSvc,
		twitterOAuthSvc: twitterOAuthSvc,
		userRepo:        userRepo,
		sessionRepo:     sessionRepo,
		jwtSecret:       cfg.JWTSecret,
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
	user, err := s.findOrCreateGoogleUser(ctx, userInfo)
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

func (s *authenticationService) InitiateTwitterAuth(state string) string {
	return s.twitterOAuthSvc.GetAuthURL(state)
}

func (s *authenticationService) CompleteTwitterAuth(ctx context.Context, code, state, userAgent, ipAddress string) (*domain.AuthResult, error) {
	token, err := s.twitterOAuthSvc.ExchangeCode(ctx, code)
	if err != nil {
		return nil, fmt.Errorf("failed to exchange twitter code: %w", err)
	}

	userInfo, err := s.twitterOAuthSvc.GetUserInfo(ctx, token)
	if err != nil {
		return nil, fmt.Errorf("failed to get twitter user info: %w", err)
	}

	user, err := s.findOrCreateTwitterUser(ctx, userInfo)
	if err != nil {
		return nil, fmt.Errorf("failed to find or create twitter user: %w", err)
	}

	tokenPair, err := s.GenerateTokenPair(user.ID, userAgent, ipAddress)
	if err != nil {
		return nil, fmt.Errorf("failed to generate tokens: %w", err)
	}

	return &domain.AuthResult{
		User:   user,
		Tokens: tokenPair,
	}, nil
}

func (s *authenticationService) AuthenticateWithGoogleIDToken(ctx context.Context, idToken, userAgent, ipAddress string) (*domain.AuthResult, error) {
	if idToken == "" {
		return nil, fmt.Errorf("id token is required")
	}

	userInfo, err := s.oauthSvc.ValidateGoogleIDToken(ctx, idToken)
	if err != nil {
		return nil, fmt.Errorf("failed to validate google id token: %w", err)
	}

	user, err := s.findOrCreateGoogleUser(ctx, userInfo)
	if err != nil {
		return nil, fmt.Errorf("failed to find or create user: %w", err)
	}

	tokenPair, err := s.GenerateTokenPair(user.ID, userAgent, ipAddress)
	if err != nil {
		return nil, fmt.Errorf("failed to generate tokens: %w", err)
	}

	return &domain.AuthResult{
		User:   user,
		Tokens: tokenPair,
	}, nil
}

func (s *authenticationService) findOrCreateGoogleUser(ctx context.Context, userInfo *domain.GoogleUserInfo) (*domain.User, error) {
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

func (s *authenticationService) findOrCreateTwitterUser(ctx context.Context, userInfo *domain.TwitterUserInfo) (*domain.User, error) {
	existingUser, err := s.userRepo.GetByTwitterID(ctx, userInfo.ID)
	if err != nil {
		return nil, err
	}

	if existingUser != nil {
		return existingUser, nil
	}

	email := userInfo.Email
	if email == "" {
		if userInfo.Username != "" {
			email = fmt.Sprintf("%s@twitter.local", userInfo.Username)
		} else {
			email = fmt.Sprintf("%s@twitter.local", userInfo.ID)
		}
	}

	name := userInfo.Name
	if name == "" {
		name = userInfo.Username
	}

	newUser := &domain.User{
		ID:            uuid.New(),
		TwitterID:     userInfo.ID,
		TwitterHandle: userInfo.Username,
		Email:         email,
		Name:          name,
		Picture:       userInfo.ProfileImageURL,
		CreatedAt:     time.Now(),
		UpdatedAt:     time.Now(),
	}

	if err := s.userRepo.Create(ctx, newUser); err != nil {
		return nil, err
	}

	return newUser, nil
}

// Token management methods
func (s *authenticationService) GenerateTokenPair(userID uuid.UUID, userAgent, ipAddress string) (*domain.TokenPair, error) {
	sessionID := uuid.New().String()
	now := time.Now()

	accessToken, err := s.generateAccessToken(userID, sessionID)
	if err != nil {
		return nil, err
	}

	refreshToken, refreshTokenJTI, err := s.generateRefreshToken(userID, sessionID)
	if err != nil {
		return nil, err
	}

	hashedRT, err := bcrypt.GenerateFromPassword([]byte(refreshToken), bcrypt.DefaultCost)
	if err != nil {
		return nil, err
	}

	session := &domain.Session{
		ID:               sessionID,
		UserID:           userID,
		RefreshToken:     refreshToken,
		RefreshTokenHash: string(hashedRT),
		RefreshTokenJTI:  refreshTokenJTI,
		ExpiresAt:        now.Add(RefreshTokenDuration),
		CreatedAt:        now,
		LastUsedAt:       now,
		UserAgent:        userAgent,
		IPAddress:        ipAddress,
	}

	if err := s.enforceSessionLimit(context.Background(), userID); err != nil {
		return nil, err
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

func (s *authenticationService) generateRefreshToken(userID uuid.UUID, sessionID string) (string, string, error) {
	jti := uuid.New().String()

	claims := &Claims{
		UserID:    userID,
		SessionID: sessionID,
		TokenType: "refresh",
		JTI:       jti,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(RefreshTokenDuration)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			ID:        jti,
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signedToken, err := token.SignedString([]byte(s.jwtSecret))
	if err != nil {
		return "", "", err
	}

	return signedToken, jti, nil
}

func (s *authenticationService) ValidateAccessTokenWithDetails(ctx context.Context, tokenString string) (*domain.AuthInfo, error) {
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

	session.LastUsedAt = time.Now()
	if err := s.sessionRepo.UpdateLastUsed(ctx, claims.SessionID); err != nil {
		return nil, fmt.Errorf("failed to update session last used: %w", err)
	}

	return &domain.AuthInfo{
		UserID:    claims.UserID,
		SessionID: claims.SessionID,
	}, nil
}

func (s *authenticationService) RefreshAccessToken(ctx context.Context, refreshToken, userAgent, ipAddress string) (*domain.TokenPair, error) {
	claims, err := s.parseRefreshTokenClaims(ctx, refreshToken)

	if err != nil {
		return nil, err
	}

	session, err := s.sessionRepo.GetByID(ctx, claims.SessionID)
	if err != nil || session == nil {
		return nil, fmt.Errorf("invalid refresh token")
	}

	if err := bcrypt.CompareHashAndPassword([]byte(session.RefreshTokenHash), []byte(refreshToken)); err != nil {
		_ = s.sessionRepo.Delete(ctx, session.ID)
		return nil, fmt.Errorf("invalid refresh token")
	}

	if session.RefreshTokenJTI != "" && session.RefreshTokenJTI != claims.JTI {
		_ = s.sessionRepo.Delete(ctx, session.ID)
		return nil, fmt.Errorf("refresh token identifier mismatch")
	}

	if time.Now().After(session.ExpiresAt) {
		_ = s.sessionRepo.Delete(context.Background(), session.ID)
		return nil, fmt.Errorf("refresh token expired")
	}

	blacklisted, err := s.sessionRepo.IsTokenBlacklisted(ctx, claims.JTI)
	if err != nil {
		return nil, err
	}
	if blacklisted {
		return nil, fmt.Errorf("token revoked")
	}

	newAccessToken, err := s.generateAccessToken(session.UserID, session.ID)
	if err != nil {
		return nil, err
	}

	session.LastUsedAt = time.Now()
	if err := s.sessionRepo.Update(ctx, session); err != nil {
		return nil, err
	}

	return &domain.TokenPair{
		AccessToken:  newAccessToken,
		RefreshToken: refreshToken,
		SessionID:    session.ID,
	}, nil
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

func (s *authenticationService) enforceSessionLimit(ctx context.Context, userID uuid.UUID) error {
	sessions, err := s.sessionRepo.GetByUserID(ctx, userID)
	if err != nil {
		return err
	}

	if len(sessions) < maxActiveSessions {
		return nil
	}
	fmt.Print("ff")

	sort.Slice(sessions, func(i, j int) bool {
		return sessions[i].LastUsedAt.Before(sessions[j].LastUsedAt)
	})

	excess := len(sessions) - maxActiveSessions - 1

	if excess <= 0 {
		return nil
	}

	errs := make(chan error, excess)
	var wg sync.WaitGroup

	for i := 0; i < excess; i++ {
		sessionID := sessions[i].ID
		wg.Add(1)
		go func(id string) {
			defer wg.Done()
			errs <- s.sessionRepo.Delete(ctx, id)
		}(sessionID)
	}

	wg.Wait()
	close(errs)

	for err := range errs {
		if err != nil {
			return err
		}
	}

	return nil
}

func (s *authenticationService) parseRefreshTokenClaims(ctx context.Context, refreshToken string) (*Claims, error) {
	token, err := jwt.ParseWithClaims(refreshToken, &Claims{}, func(token *jwt.Token) (interface{}, error) {
		if method, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		} else if method != jwt.SigningMethodHS256 {
			return nil, fmt.Errorf("unexpected HMAC algorithm: %v", method.Alg())
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

	// Backfill JTI from standard claim if not set explicitly.
	if claims.JTI == "" {
		claims.JTI = claims.ID
	}

	if claims.TokenType != "refresh" {
		return nil, fmt.Errorf("invalid token type: expected refresh, got %s", claims.TokenType)
	}

	if claims.UserID == uuid.Nil {
		return nil, fmt.Errorf("invalid user ID in token")
	}

	if claims.SessionID == "" {
		return nil, fmt.Errorf("invalid session ID in token")
	}

	if claims.JTI == "" {
		return nil, fmt.Errorf("missing token identifier")
	}

	blacklisted, err := s.sessionRepo.IsTokenBlacklisted(ctx, claims.JTI)
	if err != nil {
		return nil, fmt.Errorf("failed to check token blacklist: %w", err)
	}

	if blacklisted {
		return nil, fmt.Errorf("token revoked")
	}

	return claims, nil
}
