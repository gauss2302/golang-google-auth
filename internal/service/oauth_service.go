package service

import (
	"context"
	"encoding/json"
	"fmt"
	"googleAuth/internal/config"
	"googleAuth/internal/domain"
	"net/http"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
)

type oauthService struct {
	config *oauth2.Config
}

func NewOAuthService(cfg *config.Config) domain.OAuthService {
	return &oauthService{
		config: &oauth2.Config{
			ClientID:     cfg.GoogleClientID,
			ClientSecret: cfg.GoogleClientSecret,
			RedirectURL:  cfg.GoogleRedirectURL,
			Scopes: []string{
				"https://www.googleapis.com/auth/userinfo.email",
				"https://www.googleapis.com/auth/userinfo.profile",
			},
			Endpoint: google.Endpoint,
		},
	}
}

func (s *oauthService) GetAuthURL(state string) string {
	return s.config.AuthCodeURL(state, oauth2.AccessTypeOffline)
}

func (s *oauthService) ExchangeCode(ctx context.Context, code string) (*oauth2.Token, error) {
	return s.config.Exchange(ctx, code)
}

func (s *oauthService) GetUserInfo(ctx context.Context, token *oauth2.Token) (*domain.GoogleUserInfo, error) {
	client := s.config.Client(ctx, token)

	resp, err := client.Get("https://www.googleapis.com/oauth2/v2/userinfo")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to get user info: %s", resp.Status)
	}

	var userInfo domain.GoogleUserInfo
	if err := json.NewDecoder(resp.Body).Decode(&userInfo); err != nil {
		return nil, err
	}

	return &userInfo, nil
}
