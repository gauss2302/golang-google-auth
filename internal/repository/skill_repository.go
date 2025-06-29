package repository

import (
	"context"
	"database/sql"
	"github.com/google/uuid"
	"googleAuth/internal/domain"
)

type skillRepository struct {
	db *sql.DB
}

func NewSkillRepository(db *sql.DB) domain.SkillRepository {
	return &skillRepository{db: db}
}

func (s *skillRepository) Create(ctx context.Context, skill *domain.Skill) error {
	query := `
	INSERT INTO skills (id, user_id, name, category, proficiency, created_at, updated_at)
	VALUES ($1, $2, $3, $4, $5, $6, $7)`

	_, err := s.db.ExecContext(ctx, query, skill.ID, skill.UserID, skill.Name, skill.Category, skill.Proficiency, skill.CreatedAt, skill.UpdatedAt)

	return err
}

func (s *skillRepository) GetByID(ctx context.Context, id uuid.UUID) (*domain.Skill, error) {
	skill := &domain.Skill{}

	query := `
        SELECT id, user_id, name, category, proficiency, created_at, updated_at
        FROM skills WHERE id = $1`

	err := s.db.QueryRowContext(ctx, query, id).Scan(
		&skill.ID, &skill.UserID, &skill.Name, &skill.Category,
		&skill.Proficiency, &skill.CreatedAt, &skill.UpdatedAt,
	)

	if err == sql.ErrNoRows {
		return nil, nil
	}

	return skill, nil
}

func (s *skillRepository) GetByUserID(ctx context.Context, UserID uuid.UUID) ([]*domain.Skill, error) {
	query := `
	SELECT id, user_id, category, proficiency, creared_at, updated_at
	FROM skills
	WHERE user_id = $1
	ORDER BY category, name`

	rows, err := s.db.QueryContext(ctx, query, UserID)
	if err != nil {
		return nil, err
	}

	defer rows.Close()

	var skills []*domain.Skill
	for rows.Next() {
		skill := &domain.Skill{}
		err := rows.Scan(&skill.ID, &skill.UserID, &skill.Name, &skill.Category,
			&skill.Proficiency, &skill.CreatedAt, &skill.UpdatedAt)
		if err != nil {
			return nil, err
		}
		skills = append(skills, skill)
	}

	if err = rows.Err(); err != nil {
		return nil, err
	}
	return skills, nil
}

func (s *skillRepository) GetByUserIDAndCategory(ctx context.Context, userID uuid.UUID, category string) ([]*domain.Skill, error) {
	query := `
	SELECT id, user_id, name, category, proficiency, created_at, updated_at
	FROM skills
	WHERE user_id = $1 AND category = $2
	ORDER BY name`

	rows, err := s.db.QueryContext(ctx, query, userID, category)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var skills []*domain.Skill
	for rows.Next() {
		skill := &domain.Skill{}
		err := rows.Scan(&skill.ID, &skill.UserID, &skill.Name, &skill.Category,
			&skill.Proficiency, &skill.CreatedAt, &skill.UpdatedAt)
		if err != nil {
			return nil, err
		}
		skills = append(skills, skill)
	}

	if err = rows.Err(); err != nil {
		return nil, err
	}

	return skills, err

}

func (s *skillRepository) Update(ctx context.Context, skill *domain.Skill) error {
	query := `
        UPDATE skills 
        SET name = $2, category = $3, proficiency = $4, updated_at = $5
        WHERE id = $1`

	result, err := s.db.ExecContext(ctx, query, skill.ID, skill.Name, skill.Category, skill.Proficiency, skill.UpdatedAt)

	if err != nil {
		return err
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return nil
	}

	if rowsAffected == 0 {
		return nil
	}

	return nil
}

func (s *skillRepository) Delete(ctx context.Context, id uuid.UUID) error {
	query := `DELETE FROM skills WHERE id = $1`

	result, err := s.db.ExecContext(ctx, query, id)
	if err != nil {
		return err
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return err
	}

	if rowsAffected == 0 {
		return nil
	}

	return nil

}

func (s *skillRepository) DeleteByUserID(ctx context.Context, userID uuid.UUID) error {
	query := `DELETE FROM skills WHERE user_id = $1`

	_, err := s.db.ExecContext(ctx, query, userID)

	return err
}

func (s *skillRepository) CountByUserID(ctx context.Context, userID uuid.UUID) (int, error) {
	var count int
	query := `SELECT COUNT(*) FROM skills WHERE user_id = $1`

	err := s.db.QueryRowContext(ctx, query, userID).Scan(&count)
	return count, err
}

func (s *skillRepository) GetCategoriesByUserID(ctx context.Context, userID uuid.UUID) ([]string, error) {
	query := `
        SELECT DISTINCT category 
        FROM skills 
        WHERE user_id = $1 
        ORDER BY category`

	rows, err := s.db.QueryContext(ctx, query, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var categories []string
	for rows.Next() {
		var category string
		if err := rows.Scan(&category); err != nil {
			return nil, err
		}
		categories = append(categories, category)
	}

	return categories, rows.Err()
}
