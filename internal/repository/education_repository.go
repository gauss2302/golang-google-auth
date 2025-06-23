package repository

import (
	"context"
	"database/sql"
	"time"

	"github.com/google/uuid"
	"github.com/rs/zerolog/log"
	"googleAuth/internal/domain"
)

const (
	dateFormat = "2006-01-02"
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
		return uuid.Nil, err
	}

	id := uuid.New()
	now := time.Now()
	startDate, endDate := r.parseEducationDates(education)

	var returnedId uuid.UUID
	err := r.db.QueryRowContext(
		ctx, query, id, resumeId, education.Institution, education.Location,
		education.Degree, education.Field, startDate, endDate, education.Description, now, now,
	).Scan(&returnedId)

	if err != nil {
		log.Error().Err(err).Msg("failed to add education")
		return uuid.Nil, err
	}

	return returnedId, nil
}

func (r *postgresEduRepository) UpdateEducation(ctx context.Context, id uuid.UUID, education *domain.Education) error {
	query := `
       UPDATE education
       SET institution = $1, location = $2, degree = $3, field = $4,
           start_date = $5, end_date = $6, description = $7, updated_at = $8
       WHERE id = $9`

	education.BeforeSave()
	if err := education.Validate(); err != nil {
		return err
	}

	now := time.Now()
	startDate, endDate := r.parseEducationDates(education)

	result, err := r.db.ExecContext(
		ctx, query, education.Institution, education.Location, education.Degree,
		education.Field, startDate, endDate, education.Description, now, id,
	)

	if err != nil {
		log.Error().Err(err).Msg("failed to update education")
		return err
	}

	return r.checkRowsAffected(result, "update education")
}

func (r *postgresEduRepository) DeleteEducation(ctx context.Context, id uuid.UUID) error {
	query := `DELETE FROM education WHERE id = $1`

	result, err := r.db.ExecContext(ctx, query, id)
	if err != nil {
		log.Error().Err(err).Msg("failed to delete education")
		return err
	}

	return r.checkRowsAffected(result, "delete education")
}

func (r *postgresEduRepository) GetEducation(ctx context.Context, id uuid.UUID) (*domain.Education, error) {
	query := `
       SELECT institution, location, degree, field, start_date, end_date, description
       FROM education
       WHERE id = $1`

	var edu educationRow
	row := r.db.QueryRowContext(ctx, query, id)
	err := row.Scan(&edu.Institution, &edu.Location, &edu.Degree, &edu.Field,
		&edu.StartDate, &edu.EndDate, &edu.Description)

	if err != nil {
		if err == sql.ErrNoRows {
			return nil, sql.ErrNoRows
		}
		log.Error().Err(err).Msg("failed to get education")
		return nil, err
	}

	return r.mapToEducationDomain(&edu), nil
}

// Helper types and methods for clean separation of concerns

type educationRow struct {
	Institution string
	Location    string
	Degree      string
	Field       string
	StartDate   time.Time
	EndDate     *time.Time
	Description string
}

func (r *postgresEduRepository) mapToEducationDomain(edu *educationRow) *domain.Education {
	startDate := edu.StartDate.Format(dateFormat)
	endDate := "Present"
	if edu.EndDate != nil {
		endDate = edu.EndDate.Format(dateFormat)
	}

	return &domain.Education{
		Institution: edu.Institution,
		Location:    edu.Location,
		Degree:      edu.Degree,
		Field:       edu.Field,
		StartDate:   startDate,
		EndDate:     endDate,
		Description: edu.Description,
	}
}

func (r *postgresEduRepository) parseEducationDates(education *domain.Education) (*time.Time, *time.Time) {
	var startDate, endDate *time.Time

	if education.StartDate != "" && education.StartDate != "Present" {
		if parsed, err := time.Parse(dateFormat, education.StartDate); err == nil {
			startDate = &parsed
		}
	}

	if education.EndDate != "" && education.EndDate != "Present" {
		if parsed, err := time.Parse(dateFormat, education.EndDate); err == nil {
			endDate = &parsed
		}
	}

	return startDate, endDate
}

func (r *postgresEduRepository) checkRowsAffected(result sql.Result, operation string) error {
	rowsAffected, err := result.RowsAffected()
	if err != nil {
		log.Error().Err(err).Msgf("failed to get rows affected for %s", operation)
		return err
	}

	if rowsAffected == 0 {
		return sql.ErrNoRows
	}

	return nil
}
