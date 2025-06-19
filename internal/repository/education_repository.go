package repository

import (
	"context"
	"database/sql"
	"errors"
	"github.com/google/uuid"
	"github.com/rs/zerolog/log"
	"googleAuth/internal/domain"
	"time"
)

type postgresEduRepository struct {
	db *sql.DB
}

func NewPostgresEduRepository(db *sql.DB) domain.EducationRepository {
	return &postgresEduRepository{
		db: db,
	}
}

func (r *postgresEduRepository) AddEducation(ctx context.Context, resumeId uuid.UUID, education *domain.Education) (uuid.UUID, error) {
	query := `INSERT INTO education (
            id, resume_id, institution, location, degree, field, start_date, end_date, description, created_at, updated_at
			)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
			RETURNING id`

	education.BeforeSave()
	if err := education.Validate(); err != nil {
		return uuid.New(), err
	}

	id := uuid.New()
	now := time.Now()

	var startDate *time.Time
	var endDate *time.Time
	var returnedId uuid.UUID

	err := r.db.QueryRowContext(
		ctx, query, id, resumeId, education.Institution, education.Location, education.Degree, education.Field, startDate, endDate, education.Description, now, now).Scan(&returnedId)

	if err != nil {
		log.Error().Err(err).Msg("failed to add education")
		return uuid.Nil, err
	}
	return returnedId, nil
}

func (r *postgresEduRepository) UpdateEducation(ctx context.Context, id uuid.UUID, education *domain.Education) error {
	query := `
		UPDATE education
		SET institution = $1,
			location = $2,
			degree = $3,
			field = $4,
			start_date = $5,
			end_date = $6,
			description = $7,
			updated_at = $8
		WHERE id = $9
	`

	education.BeforeSave()

	if err := education.Validate(); err != nil {
		return err
	}
	now := time.Now()

	var startDate *time.Time
	var endDate *time.Time

	result, err := r.db.ExecContext(
		ctx,
		query,
		education.Institution,
		education.Location,
		education.Degree,
		education.Field,
		startDate,
		endDate,
		education.Description,
		now,
		id,
	)

	if err != nil {
		log.Error().Err(err).Msg("failed to update education")
		return err
	}

	rowsAffected, err := result.RowsAffected()

	if err != nil {
		log.Error().Err(err).Msg("failed to get rows affected")
		return err
	}

	if rowsAffected == 0 {
		return sql.ErrNoRows
	}

	return nil
}

func (r *postgresEduRepository) DeleteEducation(ctx context.Context, id uuid.UUID) error {
	query := `
	DELETE FROM education
	WHERE id = $1
		`

	result, err := r.db.ExecContext(ctx, query, id)
	if err != nil {
		log.Error().Err(err).Msg("failed to delete education")
		return err
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		log.Error().Err(err).Msg("failed to get rows affected")
		return err
	}

	if rowsAffected == 0 {
		return sql.ErrNoRows
	}

	return nil
}

func (r *postgresEduRepository) GetEducation(ctx context.Context, id uuid.UUID) (*domain.Education, error) {
	query := `
		SELECT institution, location, degree, field,
				start_date, end_date, description
		FROM education
		WHERE id = $1
		`

	var edu struct {
		Institution string     `db:"institution"`
		Location    string     `db:"location"`
		Degree      string     `db:"degree"`
		Field       string     `db:"field"`
		StartDate   time.Time  `db:"start_date"`
		EndDate     *time.Time `db:"end_date"`
		Description string     `db:"description"`
	}

	err := r.db.QueryRowContext(ctx, query, &edu, id)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, sql.ErrNoRows
		}
		return nil, err
	}

	startDate := edu.StartDate.Format("2006-01-02")
	var endDate string
	if edu.EndDate != nil {
		endDate = edu.EndDate.Format("2006-01-02")
	} else {
		endDate = "Present"
	}

	education := &domain.Education{
		Institution: edu.Institution,
		Location:    edu.Location,
		Degree:      edu.Degree,
		Field:       edu.Field,
		StartDate:   startDate,
		EndDate:     endDate,
		Description: edu.Description,
	}

	return education, err
}
