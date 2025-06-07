package repository

import (
	"context"
	"database/sql"
	"github.com/google/uuid"
	"googleAuth/internal/domain"
)

type userRepository struct {
	db *sql.DB
}

func NewUserRepository(db *sql.DB) domain.UserRepository {
	return &userRepository{db: db}
}

func (r *userRepository) Create(ctx context.Context, user *domain.User) error {
	query := `
        INSERT INTO users (id, google_id, email, name, picture, created_at, updated_at)
        VALUES ($1, $2, $3, $4, $5, $6, $7)`

	_, err := r.db.ExecContext(ctx, query,
		user.ID, user.GoogleID, user.Email, user.Name, user.Picture,
		user.CreatedAt, user.UpdatedAt)

	return err
}

func (r *userRepository) GetByID(ctx context.Context, id uuid.UUID) (*domain.User, error) {
	user := &domain.User{}
	query := `
        SELECT id, google_id, email, name, picture, created_at, updated_at
        FROM users WHERE id = $1`

	err := r.db.QueryRowContext(ctx, query, id).Scan(
		&user.ID, &user.GoogleID, &user.Email, &user.Name, &user.Picture,
		&user.CreatedAt, &user.UpdatedAt)

	if err == sql.ErrNoRows {
		return nil, nil
	}

	return user, err
}

func (r *userRepository) GetByGoogleID(ctx context.Context, googleID string) (*domain.User, error) {
	user := &domain.User{}
	query := `
        SELECT id, google_id, email, name, picture, created_at, updated_at
        FROM users WHERE google_id = $1`

	err := r.db.QueryRowContext(ctx, query, googleID).Scan(
		&user.ID, &user.GoogleID, &user.Email, &user.Name, &user.Picture,
		&user.CreatedAt, &user.UpdatedAt)

	if err == sql.ErrNoRows {
		return nil, nil
	}

	return user, err
}

func (r *userRepository) GetByEmail(ctx context.Context, email string) (*domain.User, error) {
	user := &domain.User{}
	query := `
        SELECT id, google_id, email, name, picture, created_at, updated_at
        FROM users WHERE email = $1`

	err := r.db.QueryRowContext(ctx, query, email).Scan(
		&user.ID, &user.GoogleID, &user.Email, &user.Name, &user.Picture,
		&user.CreatedAt, &user.UpdatedAt)

	if err == sql.ErrNoRows {
		return nil, nil
	}

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
