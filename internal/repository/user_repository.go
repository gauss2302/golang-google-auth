package repository

import (
	"context"
	"database/sql"
	"fmt"
	"googleAuth/internal/domain"

	"github.com/google/uuid"
)

type userRepository struct {
	db *sql.DB
}

func NewUserRepository(db *sql.DB) domain.UserRepository {
	return &userRepository{db: db}
}

func (r *userRepository) Create(ctx context.Context, user *domain.User) error {
	query := `
        INSERT INTO users (id, google_id, twitter_id, twitter_handle, email, name, picture, created_at, updated_at)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`

	_, err := r.db.ExecContext(ctx, query,
		user.ID,
		nullString(user.GoogleID),
		nullString(user.TwitterID),
		nullString(user.TwitterHandle),
		user.Email,
		user.Name,
		user.Picture,
		user.CreatedAt,
		user.UpdatedAt,
	)

	return err
}

func (r *userRepository) CreateByEmailAndPassword(ctx context.Context, user *domain.User) (*domain.User, error) {

	if user == nil {
		return nil, fmt.Errorf("user cannot be nil")
	}

	userModel := &domain.User{}
	query := `
			INSERT INTO users (id, email, hashed_password, first_name, last_name, created_at, updated_at)
			VALUES ($1, $2, $3, $4, $5, $6, $7)
			`

	err := r.db.QueryRowContext(ctx, query,
		user.ID,
		user.Email,
		user.HashedPassword,
		user.FirstName,
		user.LastName,
		user.CreatedAt,
		user.UpdatedAt,
	).Scan(
		&userModel.ID,
		&userModel.Email,
		&userModel.FirstName,
		&userModel.LastName,
		&userModel.CreatedAt,
		&userModel.UpdatedAt,
	)

	if err != nil {
		return nil, err
	}

	return userModel, nil
}

func (r *userRepository) GetByID(ctx context.Context, id uuid.UUID) (*domain.User, error) {
	user := &domain.User{}
	query := `
        SELECT id, google_id, twitter_id, twitter_handle, email, name, picture, created_at, updated_at
        FROM users WHERE id = $1`

	var googleID, twitterID, twitterHandle sql.NullString
	err := r.db.QueryRowContext(ctx, query, id).Scan(
		&user.ID,
		&googleID,
		&twitterID,
		&twitterHandle,
		&user.Email,
		&user.Name,
		&user.Picture,
		&user.CreatedAt,
		&user.UpdatedAt,
	)

	if err == sql.ErrNoRows {
		return nil, nil
	}

	user.GoogleID = googleID.String
	user.TwitterID = twitterID.String
	user.TwitterHandle = twitterHandle.String

	return user, err
}

func (r *userRepository) GetByGoogleID(ctx context.Context, googleID string) (*domain.User, error) {
	user := &domain.User{}
	query := `
        SELECT id, google_id, twitter_id, twitter_handle, email, name, picture, created_at, updated_at
        FROM users WHERE google_id = $1`

	var dbGoogleID, twitterID, twitterHandle sql.NullString
	err := r.db.QueryRowContext(ctx, query, googleID).Scan(
		&user.ID,
		&dbGoogleID,
		&twitterID,
		&twitterHandle,
		&user.Email,
		&user.Name,
		&user.Picture,
		&user.CreatedAt,
		&user.UpdatedAt,
	)

	if err == sql.ErrNoRows {
		return nil, nil
	}

	user.GoogleID = dbGoogleID.String
	user.TwitterID = twitterID.String
	user.TwitterHandle = twitterHandle.String

	return user, err
}

func (r *userRepository) GetByTwitterID(ctx context.Context, twitterID string) (*domain.User, error) {
	user := &domain.User{}
	query := `
        SELECT id, google_id, twitter_id, twitter_handle, email, name, picture, created_at, updated_at
        FROM users WHERE twitter_id = $1`

	var googleID, dbTwitterID sql.NullString
	err := r.db.QueryRowContext(ctx, query, twitterID).Scan(
		&user.ID,
		&googleID,
		&dbTwitterID,
		&user.TwitterHandle,
		&user.Email,
		&user.Name,
		&user.Picture,
		&user.CreatedAt,
		&user.UpdatedAt,
	)

	if err == sql.ErrNoRows {
		return nil, nil
	}

	user.GoogleID = googleID.String
	user.TwitterID = dbTwitterID.String

	return user, err
}

func (r *userRepository) GetByEmail(ctx context.Context, email string) (*domain.User, error) {
	user := &domain.User{}
	query := `
        SELECT id, google_id, twitter_id, twitter_handle, email, name, picture, created_at, updated_at
        FROM users WHERE email = $1`

	var googleID, twitterID, twitterHandle sql.NullString
	err := r.db.QueryRowContext(ctx, query, email).Scan(
		&user.ID,
		&googleID,
		&twitterID,
		&twitterHandle,
		&user.Email,
		&user.Name,
		&user.Picture,
		&user.CreatedAt,
		&user.UpdatedAt,
	)

	if err == sql.ErrNoRows {
		return nil, nil
	}

	user.GoogleID = googleID.String
	user.TwitterID = twitterID.String
	user.TwitterHandle = twitterHandle.String

	return user, err
}

func (r *userRepository) Update(ctx context.Context, user *domain.User) error {
	query := `
        UPDATE users 
        SET name = $2, picture = $3, updated_at = $4
        WHERE id = $1`

	_, err := r.db.ExecContext(ctx, query,
		user.ID, user.Name, user.Picture, user.UpdatedAt)

	return err
}

func nullString(value string) sql.NullString {
	if value == "" {
		return sql.NullString{}
	}
	return sql.NullString{
		String: value,
		Valid:  true,
	}
}
