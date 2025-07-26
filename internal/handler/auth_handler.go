package handler

import (
	"fmt"
	"googleAuth/internal/config"
	"googleAuth/internal/domain"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

type AuthHandler struct {
	authService domain.AuthenticationService
	config      *config.Config
}

func NewAuthHandler(authService domain.AuthenticationService, cfg *config.Config) *AuthHandler {
	return &AuthHandler{
		authService: authService,
		config:      cfg,
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
	c.SetCookie("oauth_state", "", -1, "/", "", false, true)

	// Получаем информацию о пользователе и клиенте
	userAgent := c.GetHeader("User-Agent")
	ipAddress := c.ClientIP()

	// Вся сложная логика теперь инкапсулирована в сервисе
	authResult, err := h.authService.CompleteGoogleAuth(
		c.Request.Context(),
		code,
		state,
		userAgent,
		ipAddress,
	)
	if err != nil {
		// Логируем ошибку и перенаправляем пользователя
		frontendURL := fmt.Sprintf("%s/auth/login?error=auth_failed", h.config.FrontendURL)
		c.Redirect(http.StatusTemporaryRedirect, frontendURL)
		return
	}

	// Генерируем безопасный auth code для обмена на фронтенде
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

func (h *AuthHandler) ExchangeAuthCode(c *gin.Context) {
	var req struct {
		AuthCode string `json:"auth_code" binding:"required"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Обмениваем временный код на результат аутентификации
	authResult, err := h.authService.ExchangeAuthCode(req.AuthCode)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid or expired auth code"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"user":   authResult.User,
		"tokens": authResult.Tokens,
	})
}

func (h *AuthHandler) RefreshToken(c *gin.Context) {
	var req struct {
		RefreshToken string `json:"refresh_token" binding:"required"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	userAgent := c.GetHeader("User-Agent")
	ipAddress := c.ClientIP()

	// Используем новый сервис для обновления токенов
	tokenPair, err := h.authService.RefreshAccessToken(req.RefreshToken, userAgent, ipAddress)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid refresh token"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"tokens": tokenPair})
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

	c.JSON(http.StatusOK, gin.H{"message": "Logged out successfully"})
}

func (h *AuthHandler) GetSessions(c *gin.Context) {
	userID, exists := c.Get("user_id")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "User not authenticated"})
		return
	}

	// Используем новый сервис для получения сессий
	sessions, err := h.authService.GetUserSessions(userID.(uuid.UUID))
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get sessions"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"sessions": sessions})
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

	// Проверяем, что сессия принадлежит пользователю
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

	// Отзываем сессию
	if err := h.authService.RevokeSession(sessionID); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to revoke session"})
		return
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

	c.JSON(http.StatusOK, gin.H{"message": "All sessions revoked successfully"})
}
