package service

import (
	"context"
	"encoding/json"
	"fmt"
	"googleAuth/internal/config"
	"googleAuth/internal/domain"
	"net/http"

	"golang.org/x/oauth2"
)

type twitterOAuthService struct {
	config *oauth2.Config
}

func NewTwitterOAuthService(cfg *config.Config) domain.TwitterOAuthService {
	return &twitterOAuthService{
		config: &oauth2.Config{
			ClientID:     cfg.TwitterClientID,
			ClientSecret: cfg.TwitterClientSecret,
			RedirectURL:  cfg.TwitterRedirectURL,
			Scopes: []string{
				"tweet.read",
				"users.read",
				"offline.access",
			},
			Endpoint: oauth2.Endpoint{
				AuthURL:  "https://twitter.com/i/oauth2/authorize",
				TokenURL: "https://api.twitter.com/2/oauth2/token",
			},
		},
	}
}

func (s *twitterOAuthService) GetAuthURL(state string) string {
	return s.config.AuthCodeURL(state, oauth2.AccessTypeOffline)
}

func (s *twitterOAuthService) ExchangeCode(ctx context.Context, code string) (*oauth2.Token, error) {
	return s.config.Exchange(ctx, code)
}

func (s *twitterOAuthService) GetUserInfo(ctx context.Context, token *oauth2.Token) (*domain.TwitterUserInfo, error) {
	client := s.config.Client(ctx, token)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.twitter.com/2/users/me?user.fields=profile_image_url,name,username", nil)
	if err != nil {
		return nil, err
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to get twitter user info: %s", resp.Status)
	}

	var userResponse struct {
		Data struct {
			ID              string `json:"id"`
			Name            string `json:"name"`
			Username        string `json:"username"`
			ProfileImageURL string `json:"profile_image_url"`
		} `json:"data"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&userResponse); err != nil {
		return nil, err
	}

	if userResponse.Data.ID == "" {
		return nil, fmt.Errorf("twitter user info is empty")
	}

	return &domain.TwitterUserInfo{
		ID:              userResponse.Data.ID,
		Name:            userResponse.Data.Name,
		Username:        userResponse.Data.Username,
		ProfileImageURL: userResponse.Data.ProfileImageURL,
	}, nil
}
