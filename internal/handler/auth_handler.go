package handler

import (
	"fmt"
	"googleAuth/internal/config"
	"googleAuth/internal/domain"
	"googleAuth/internal/service"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

type AuthHandler struct {
	authService   domain.AuthenticationService
	config        *config.Config
	refreshCookie *service.CookieConfig
}

func NewAuthHandler(authService domain.AuthenticationService, cfg *config.Config) *AuthHandler {
	return &AuthHandler{
		authService: authService,
		config:      cfg,
		refreshCookie: func() *service.CookieConfig {
			cookieCfg := service.DefaultCookieConfig()
			cookieCfg.Secure = cfg.CookieSecure
			return cookieCfg
		}(),
	}
}

func (h *AuthHandler) GoogleAuth(c *gin.Context) {
	state := uuid.New().String()

	// Устанавливаем cookie с state для CSRF защиты
	c.SetCookie("oauth_state", state, 600, "/", "", h.config.CookieSecure, true)

	// Используем новый сервис
	url := h.authService.InitiateGoogleAuth(state)
	c.JSON(http.StatusOK, gin.H{"auth_url": url})
}

func (h *AuthHandler) GoogleCallback(c *gin.Context) {
	state := c.Query("state")
	code := c.Query("code")

	// Проверяем state для защиты от CSRF
	storedState, err := c.Cookie("oauth_state")
	if err != nil || state != storedState {
		frontendURL := fmt.Sprintf("%s/auth/login?error=invalid_state", h.config.FrontendURL)
		c.Redirect(http.StatusTemporaryRedirect, frontendURL)
		return
	}

	// Очищаем state cookie
	c.SetCookie("oauth_state", "", -1, "/", "", h.config.CookieSecure, true)

	// Получаем информацию о пользователе и клиенте
	userAgent := c.GetHeader("User-Agent")
	ipAddress := c.ClientIP()

	authResult, err := h.authService.CompleteGoogleAuth(
		c.Request.Context(),
		code,
		state,
		userAgent,
		ipAddress,
	)
	if err != nil {
		frontendURL := fmt.Sprintf("%s/auth/login?error=auth_failed", h.config.FrontendURL)
		c.Redirect(http.StatusTemporaryRedirect, frontendURL)
		return
	}
	authCode := uuid.New().String()
	if err := h.authService.StoreTemporaryAuth(authCode, authResult, 5*time.Minute); err != nil {
		frontendURL := fmt.Sprintf("%s/auth/login?error=storage_failed", h.config.FrontendURL)
		c.Redirect(http.StatusTemporaryRedirect, frontendURL)
		return
	}

	// Перенаправляем на фронтенд с временным кодом
	frontendURL := fmt.Sprintf("%s/auth/callback?auth_code=%s", h.config.FrontendURL, authCode)
	c.Redirect(http.StatusTemporaryRedirect, frontendURL)
}

func (h *AuthHandler) MobileLogin(c *gin.Context) {
	h.handleMobileAuth(c, http.StatusOK)
}

func (h *AuthHandler) MobileRegister(c *gin.Context) {
	h.handleMobileAuth(c, http.StatusCreated)
}

func (h *AuthHandler) handleMobileAuth(c *gin.Context, successStatus int) {
	var req struct {
		IDToken string `json:"id_token" binding:"required"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Invalid request",
			"code":  "INVALID_REQUEST",
			"details": err.Error(),
		})
		return
	}

	if req.IDToken == "" {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "ID token is required",
			"code":  "MISSING_ID_TOKEN",
		})
		return
	}

	userAgent := c.GetHeader("User-Agent")
	ipAddress := c.ClientIP()

	authResult, err := h.authService.AuthenticateWithGoogleIDToken(c.Request.Context(), req.IDToken, userAgent, ipAddress)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{
			"error": "Invalid or expired ID token",
			"code":  "INVALID_ID_TOKEN",
		})
		return
	}

	if authResult.Tokens == nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Token generation failed"})
		return
	}

	h.setRefreshTokenCookie(c, authResult.Tokens.RefreshToken)

	c.JSON(successStatus, gin.H{
		"user": authResult.User,
		"tokens": gin.H{
			"access_token": authResult.Tokens.AccessToken,
			"session_id":   authResult.Tokens.SessionID,
		},
		"session": gin.H{
			"id":                 authResult.Tokens.SessionID,
			"refresh_expires_at": time.Now().Add(service.RefreshTokenDuration),
		},
	})
}

func (h *AuthHandler) TwitterAuth(c *gin.Context) {
	state := uuid.New().String()

	c.SetCookie("oauth_state", state, 600, "/", "", h.config.CookieSecure, true)

	url := h.authService.InitiateTwitterAuth(state)
	c.JSON(http.StatusOK, gin.H{"auth_url": url})
}

func (h *AuthHandler) TwitterCallback(c *gin.Context) {
	state := c.Query("state")
	code := c.Query("code")

	storedState, err := c.Cookie("oauth_state")
	if err != nil || state != storedState {
		frontendURL := fmt.Sprintf("%s/auth/login?error=invalid_state", h.config.FrontendURL)
		c.Redirect(http.StatusTemporaryRedirect, frontendURL)
		return
	}

	c.SetCookie("oauth_state", "", -1, "/", "", h.config.CookieSecure, true)

	userAgent := c.GetHeader("User-Agent")
	ipAddress := c.ClientIP()

	authResult, err := h.authService.CompleteTwitterAuth(
		c.Request.Context(),
		code,
		state,
		userAgent,
		ipAddress,
	)
	if err != nil {
		frontendURL := fmt.Sprintf("%s/auth/login?error=auth_failed", h.config.FrontendURL)
		c.Redirect(http.StatusTemporaryRedirect, frontendURL)
		return
	}

	authCode := uuid.New().String()
	if err := h.authService.StoreTemporaryAuth(authCode, authResult, 5*time.Minute); err != nil {
		frontendURL := fmt.Sprintf("%s/auth/login?error=storage_failed", h.config.FrontendURL)
		c.Redirect(http.StatusTemporaryRedirect, frontendURL)
		return
	}

	frontendURL := fmt.Sprintf("%s/auth/callback?auth_code=%s", h.config.FrontendURL, authCode)
	c.Redirect(http.StatusTemporaryRedirect, frontendURL)
}

func (h *AuthHandler) ExchangeAuthCode(c *gin.Context) {
	var req struct {
		AuthCode string `json:"auth_code" binding:"required"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Invalid request",
			"code":  "INVALID_REQUEST",
			"details": err.Error(),
		})
		return
	}

	if req.AuthCode == "" {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Auth code is required",
			"code":  "MISSING_AUTH_CODE",
		})
		return
	}

	// Обмениваем временный код на результат аутентификации
	authResult, err := h.authService.ExchangeAuthCode(req.AuthCode)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Invalid or expired auth code",
			"code":  "INVALID_AUTH_CODE",
		})
		return
	}

	if authResult.Tokens == nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Token generation failed"})
		return
	}

	h.setRefreshTokenCookie(c, authResult.Tokens.RefreshToken)

	c.JSON(http.StatusOK, gin.H{
		"user": authResult.User,
		"access_token": authResult.Tokens.AccessToken,
		"expires_in":   int(service.AccessTokenDuration.Seconds()),
		"session_id":   authResult.Tokens.SessionID,

	})
}

func (h *AuthHandler) RefreshToken(c *gin.Context) {
	userAgent := c.GetHeader("User-Agent")
	ipAddress := c.ClientIP()

	// Get refresh token from HTTP-only cookie
	refreshToken, err := c.Cookie(h.refreshCookie.Name)
	if err != nil || refreshToken == "" {
		c.JSON(http.StatusUnauthorized, gin.H{
			"error": "Refresh token missing",
			"code":  "REFRESH_TOKEN_MISSING",
		})
		return
	}

	tokenPair, err := h.authService.RefreshAccessToken(c.Request.Context(), refreshToken, userAgent, ipAddress)
	if err != nil {
		// Clear invalid refresh token cookie
		h.clearRefreshTokenCookie(c)
		c.JSON(http.StatusUnauthorized, gin.H{
			"error": "Invalid or expired refresh token",
			"code":  "REFRESH_TOKEN_INVALID",
		})
		return
	}

	// If refresh token was rotated, update the cookie
	if tokenPair.RefreshToken != refreshToken {
		h.setRefreshTokenCookie(c, tokenPair.RefreshToken)
	}

	// Return new access token
	c.JSON(http.StatusOK, gin.H{
		"access_token": tokenPair.AccessToken,
		"expires_in":   int(service.AccessTokenDuration.Seconds()),
		"session_id":   tokenPair.SessionID,
	})
}

func (h *AuthHandler) Logout(c *gin.Context) {
	sessionID, exists := c.Get("session_id")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Session not found"})
		return
	}

	if err := h.authService.RevokeSession(sessionID.(string)); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to revoke session"})
		return
	}

	// Clear refresh token cookie
	h.clearRefreshTokenCookie(c)

	c.JSON(http.StatusOK, gin.H{"message": "Logged out successfully"})
}


func (h *AuthHandler) GetSessions(c *gin.Context) {
	userID, exists := c.Get("user_id")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "User not authenticated"})
		return
	}

	sessions, err := h.authService.GetUserSessions(userID.(uuid.UUID))
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get sessions"})
		return
	}

	// Sanitize sessions before returning (remove sensitive data)
	sanitizedSessions := make([]gin.H, len(sessions))
	for i, session := range sessions {
		sanitizedSessions[i] = gin.H{
			"id":           session.ID,
			"user_agent":   session.UserAgent,
			"ip_address":   session.IPAddress,
			"created_at":   session.CreatedAt,
			"last_used_at": session.LastUsedAt,
			"expires_at":   session.ExpiresAt,
		}
	}

	c.JSON(http.StatusOK, gin.H{"sessions": sanitizedSessions})
}

func (h *AuthHandler) RevokeSession(c *gin.Context) {
	sessionID := c.Param("sessionId")
	if sessionID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Session ID required"})
		return
	}

	userID, exists := c.Get("user_id")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "User not authenticated"})
		return
	}

	sessions, err := h.authService.GetUserSessions(userID.(uuid.UUID))
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to verify session"})
		return
	}

	var found bool
	for _, session := range sessions {
		if session.ID == sessionID {
			found = true
			break
		}
	}

	if !found {
		c.JSON(http.StatusForbidden, gin.H{"error": "Session not found or unauthorized"})
		return
	}

	if err := h.authService.RevokeSession(sessionID); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to revoke session"})
		return
	}

	// If revoking current session, clear cookie
	currentSessionID, _ := c.Get("session_id")
	if currentSessionID == sessionID {
		h.clearRefreshTokenCookie(c)
	}

	c.JSON(http.StatusOK, gin.H{"message": "Session revoked successfully"})
}

func (h *AuthHandler) RevokeAllSessions(c *gin.Context) {
	userID, exists := c.Get("user_id")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "User not authenticated"})
		return
	}

	// Используем новый сервис для отзыва всех сессий
	if err := h.authService.RevokeAllUserSessions(userID.(uuid.UUID)); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to revoke all sessions"})
		return
	}

	h.clearRefreshTokenCookie(c)

	c.JSON(http.StatusOK, gin.H{"message": "All sessions revoked successfully"})
}

func (h *AuthHandler) CheckAuthStatus(c *gin.Context) {
	authenticated, _ := c.Get("authenticated")
	if auth, ok := authenticated.(bool); ok && auth {
		userID, _ := c.Get("user_id")
		sessionID, _ := c.Get("session_id")
		
		c.JSON(http.StatusOK, gin.H{
			"authenticated": true,
			"user_id":       userID,
			"session_id":    sessionID,
		})
		return
	}

	// Check if refresh token exists (can be used for silent refresh)
	_, err := c.Cookie(h.refreshCookie.Name)
	hasRefreshToken := err == nil

	c.JSON(http.StatusOK, gin.H{
		"authenticated":     false,
		"has_refresh_token": hasRefreshToken,
	})
}

func (h *AuthHandler) setRefreshTokenCookie(c *gin.Context, refreshToken string) {
	cookie := &http.Cookie{
		Name:     h.refreshCookie.Name,
		Value:    refreshToken,
		Path:     h.refreshCookie.Path,
		Domain:   h.refreshCookie.Domain,
		MaxAge:   int(service.RefreshTokenDuration.Seconds()),
		HttpOnly: true,  // Cannot be accessed by JavaScript
		Secure:   h.refreshCookie.Secure,
		SameSite: http.SameSiteStrictMode, // CSRF protection
	}

	http.SetCookie(c.Writer, cookie)
}
func (h *AuthHandler) clearRefreshTokenCookie(c *gin.Context) {
	cookie := &http.Cookie{
		Name:     h.refreshCookie.Name,
		Value:    "",
		Path:     h.refreshCookie.Path,
		Domain:   h.refreshCookie.Domain,
		MaxAge:   -1, // Delete cookie
		HttpOnly: true,
		Secure:   h.refreshCookie.Secure,
		SameSite: http.SameSiteStrictMode,
	}

	http.SetCookie(c.Writer, cookie)
}