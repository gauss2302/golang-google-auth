package repository

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"googleAuth/internal/domain"

	"github.com/google/uuid"
	"github.com/lib/pq"
	"github.com/rs/zerolog/log"
)

const (
	expDateFormat = "2006-01-02"
)

// Custom errors for experience repository
var (
	ErrExperienceNotFound    = errors.New("experience not found")
	ErrInvalidExperienceData = errors.New("invalid experience data")
	ErrExpDatabaseOperation  = errors.New("database operation failed")
)

type postgresExpRepository struct {
	db *sql.DB
}

// NewPostgresExpRepository creates a new PostgreSQL experience repository
func NewPostgresExpRepository(db *sql.DB) domain.ExperienceRepository {
	if db == nil {
		panic("database connection is required for experience repository")
	}
	return &postgresExpRepository{
		db: db,
	}
}

// AddExperience creates a new experience entry for a resume
func (r *postgresExpRepository) AddExperience(ctx context.Context, resumeID uuid.UUID, experience *domain.Experience) (uuid.UUID, error) {
	if experience == nil {
		return uuid.Nil, fmt.Errorf("%w: experience cannot be nil", ErrInvalidExperienceData)
	}

	if resumeID == uuid.Nil {
		return uuid.Nil, fmt.Errorf("%w: resume ID cannot be nil", ErrInvalidExperienceData)
	}

	experience.BeforeSave()
	if err := experience.Validate(); err != nil {
		return uuid.Nil, fmt.Errorf("%w: %v", ErrInvalidExperienceData, err)
	}

	query := `
		INSERT INTO experience (
			id, resume_id, employer, job_title, location, 
			start_date, end_date, description, achievements, created_at, updated_at
		)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
		RETURNING id`

	id := uuid.New()
	now := time.Now().UTC()
	startDate, endDate := r.parseExperienceDates(experience)
	achievements := r.achievementsToJSON(experience.Achievements)

	var returnedID uuid.UUID
	err := r.db.QueryRowContext(
		ctx, query,
		id, resumeID, experience.Employer, experience.JobTitle, experience.Location,
		startDate, endDate, experience.Description, achievements, now, now,
	).Scan(&returnedID)

	if err != nil {
		log.Error().
			Err(err).
			Str("resume_id", resumeID.String()).
			Str("employer", experience.Employer).
			Msg("failed to add experience")
		return uuid.Nil, fmt.Errorf("%w: %v", ErrExpDatabaseOperation, err)
	}

	log.Debug().
		Str("experience_id", returnedID.String()).
		Str("resume_id", resumeID.String()).
		Msg("experience added successfully")

	return returnedID, nil
}

// UpdateExperience updates an existing experience entry
func (r *postgresExpRepository) UpdateExperience(ctx context.Context, id uuid.UUID, experience *domain.Experience) error {
	if experience == nil {
		return fmt.Errorf("%w: experience cannot be nil", ErrInvalidExperienceData)
	}

	if id == uuid.Nil {
		return fmt.Errorf("%w: experience ID cannot be nil", ErrInvalidExperienceData)
	}

	experience.BeforeSave()
	if err := experience.Validate(); err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidExperienceData, err)
	}

	query := `
		UPDATE experience
		SET employer = $1, job_title = $2, location = $3,
			start_date = $4, end_date = $5, description = $6, 
			achievements = $7, updated_at = $8
		WHERE id = $9`

	now := time.Now().UTC()
	startDate, endDate := r.parseExperienceDates(experience)
	achievements := r.achievementsToJSON(experience.Achievements)

	result, err := r.db.ExecContext(
		ctx, query,
		experience.Employer, experience.JobTitle, experience.Location,
		startDate, endDate, experience.Description, achievements, now, id,
	)

	if err != nil {
		log.Error().
			Err(err).
			Str("experience_id", id.String()).
			Msg("failed to update experience")
		return fmt.Errorf("%w: %v", ErrExpDatabaseOperation, err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		log.Error().
			Err(err).
			Str("experience_id", id.String()).
			Msg("failed to get rows affected for update experience")
		return fmt.Errorf("%w: %v", ErrExpDatabaseOperation, err)
	}

	if rowsAffected == 0 {
		return ErrExperienceNotFound
	}

	log.Debug().
		Str("experience_id", id.String()).
		Msg("experience updated successfully")

	return nil
}

// DeleteExperience removes an experience entry by ID
func (r *postgresExpRepository) DeleteExperience(ctx context.Context, id uuid.UUID) error {
	if id == uuid.Nil {
		return fmt.Errorf("%w: experience ID cannot be nil", ErrInvalidExperienceData)
	}

	query := `DELETE FROM experience WHERE id = $1`

	result, err := r.db.ExecContext(ctx, query, id)
	if err != nil {
		log.Error().
			Err(err).
			Str("experience_id", id.String()).
			Msg("failed to delete experience")
		return fmt.Errorf("%w: %v", ErrExpDatabaseOperation, err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		log.Error().
			Err(err).
			Str("experience_id", id.String()).
			Msg("failed to get rows affected for delete experience")
		return fmt.Errorf("%w: %v", ErrExpDatabaseOperation, err)
	}

	if rowsAffected == 0 {
		return ErrExperienceNotFound
	}

	log.Debug().
		Str("experience_id", id.String()).
		Msg("experience deleted successfully")

	return nil
}

// GetExperience retrieves a single experience entry by ID
func (r *postgresExpRepository) GetExperience(ctx context.Context, id uuid.UUID) (*domain.Experience, error) {
	if id == uuid.Nil {
		return nil, fmt.Errorf("%w: experience ID cannot be nil", ErrInvalidExperienceData)
	}

	query := `
		SELECT employer, job_title, location, start_date, end_date, description, achievements
		FROM experience
		WHERE id = $1`

	var row experienceRow
	err := r.db.QueryRowContext(ctx, query, id).Scan(
		&row.Employer, &row.JobTitle, &row.Location,
		&row.StartDate, &row.EndDate, &row.Description, &row.Achievements,
	)

	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrExperienceNotFound
		}
		log.Error().
			Err(err).
			Str("experience_id", id.String()).
			Msg("failed to get experience")
		return nil, fmt.Errorf("%w: %v", ErrExpDatabaseOperation, err)
	}

	return r.mapToExperienceDomain(&row), nil
}

// GetExperienceByResume retrieves all experience entries for a resume
func (r *postgresExpRepository) GetExperienceByResume(ctx context.Context, resumeID string) ([]*domain.Experience, error) {
	parsedID, err := uuid.Parse(resumeID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid resume ID format", ErrInvalidExperienceData)
	}

	if parsedID == uuid.Nil {
		return nil, fmt.Errorf("%w: resume ID cannot be nil", ErrInvalidExperienceData)
	}

	query := `
		SELECT employer, job_title, location, start_date, end_date, description, achievements
		FROM experience
		WHERE resume_id = $1
		ORDER BY start_date DESC`

	rows, err := r.db.QueryContext(ctx, query, parsedID)
	if err != nil {
		log.Error().
			Err(err).
			Str("resume_id", resumeID).
			Msg("failed to get experiences by resume ID")
		return nil, fmt.Errorf("%w: %v", ErrExpDatabaseOperation, err)
	}
	defer rows.Close()

	var experiences []*domain.Experience
	for rows.Next() {
		var row experienceRow
		err := rows.Scan(
			&row.Employer, &row.JobTitle, &row.Location,
			&row.StartDate, &row.EndDate, &row.Description, &row.Achievements,
		)
		if err != nil {
			log.Error().
				Err(err).
				Str("resume_id", resumeID).
				Msg("failed to scan experience row")
			return nil, fmt.Errorf("%w: %v", ErrExpDatabaseOperation, err)
		}
		experiences = append(experiences, r.mapToExperienceDomain(&row))
	}

	if err := rows.Err(); err != nil {
		log.Error().
			Err(err).
			Str("resume_id", resumeID).
			Msg("error iterating experience rows")
		return nil, fmt.Errorf("%w: %v", ErrExpDatabaseOperation, err)
	}

	return experiences, nil
}

// Helper types for database row mapping

type experienceRow struct {
	Employer     string
	JobTitle     string
	Location     sql.NullString
	StartDate    time.Time
	EndDate      *time.Time
	Description  sql.NullString
	Achievements pq.StringArray
}

// mapToExperienceDomain converts a database row to domain Experience
func (r *postgresExpRepository) mapToExperienceDomain(row *experienceRow) *domain.Experience {
	startDate := row.StartDate.Format(expDateFormat)
	endDate := "Present"
	if row.EndDate != nil {
		endDate = row.EndDate.Format(expDateFormat)
	}

	achievements := make([]string, 0)
	if row.Achievements != nil {
		achievements = []string(row.Achievements)
	}

	return &domain.Experience{
		Employer:     row.Employer,
		JobTitle:     row.JobTitle,
		Location:     nullStringToStr(row.Location),
		StartDate:    startDate,
		EndDate:      endDate,
		Description:  nullStringToStr(row.Description),
		Achievements: achievements,
	}
}

// parseExperienceDates converts domain date strings to time.Time pointers
func (r *postgresExpRepository) parseExperienceDates(experience *domain.Experience) (*time.Time, *time.Time) {
	var startDate, endDate *time.Time

	if experience.StartDate != "" && experience.StartDate != "Present" {
		if parsed, err := time.Parse(expDateFormat, experience.StartDate); err == nil {
			startDate = &parsed
		}
	}

	if experience.EndDate != "" && experience.EndDate != "Present" {
		if parsed, err := time.Parse(expDateFormat, experience.EndDate); err == nil {
			endDate = &parsed
		}
	}

	return startDate, endDate
}

// achievementsToJSON converts achievements slice to JSON for storage
func (r *postgresExpRepository) achievementsToJSON(achievements []string) []byte {
	if len(achievements) == 0 {
		return []byte("[]")
	}
	data, err := json.Marshal(achievements)
	if err != nil {
		return []byte("[]")
	}
	return data
}

// nullStringToStr safely converts sql.NullString to string
func nullStringToStr(ns sql.NullString) string {
	if ns.Valid {
		return ns.String
	}
	return ""
}
