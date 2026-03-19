package repository

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"googleAuth/internal/domain"

	"github.com/google/uuid"
	"github.com/rs/zerolog/log"
)

const (
	dateFormat = "2006-01-02"
)

// Custom errors for education repository
var (
	ErrEducationNotFound      = errors.New("education not found")
	ErrEducationAlreadyExists = errors.New("education already exists")
	ErrInvalidEducationData   = errors.New("invalid education data")
	ErrDatabaseOperation      = errors.New("database operation failed")
)

// postgresEduRepository implements the EducationRepository interface
type postgresEduRepository struct {
	db *sql.DB
}

// NewPostgresEduRepository creates a new PostgreSQL education repository
func NewPostgresEduRepository(db *sql.DB) domain.EducationRepository {
	if db == nil {
		panic("database connection is required for education repository")
	}
	return &postgresEduRepository{
		db: db,
	}
}

// AddEducation creates a new education entry for a resume
func (r *postgresEduRepository) AddEducation(ctx context.Context, resumeID uuid.UUID, education *domain.Education) (uuid.UUID, error) {
	if education == nil {
		return uuid.Nil, fmt.Errorf("%w: education cannot be nil", ErrInvalidEducationData)
	}

	if resumeID == uuid.Nil {
		return uuid.Nil, fmt.Errorf("%w: resume ID cannot be nil", ErrInvalidEducationData)
	}

	// Sanitize and validate
	education.BeforeSave()
	if err := education.Validate(); err != nil {
		return uuid.Nil, fmt.Errorf("%w: %v", ErrInvalidEducationData, err)
	}

	query := `
		INSERT INTO education (
			id, resume_id, institution, location, degree, field, 
			start_date, end_date, description, created_at, updated_at
		)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
		RETURNING id`

	id := uuid.New()
	now := time.Now().UTC()
	startDate, endDate := r.parseEducationDates(education)

	var returnedID uuid.UUID
	err := r.db.QueryRowContext(
		ctx, query,
		id, resumeID, education.Institution, education.Location,
		education.Degree, education.Field, startDate, endDate,
		education.Description, now, now,
	).Scan(&returnedID)

	if err != nil {
		log.Error().
			Err(err).
			Str("resume_id", resumeID.String()).
			Str("institution", education.Institution).
			Msg("failed to add education")
		return uuid.Nil, fmt.Errorf("%w: %v", ErrDatabaseOperation, err)
	}

	log.Debug().
		Str("education_id", returnedID.String()).
		Str("resume_id", resumeID.String()).
		Msg("education added successfully")

	return returnedID, nil
}

// UpdateEducation updates an existing education entry
func (r *postgresEduRepository) UpdateEducation(ctx context.Context, id uuid.UUID, education *domain.Education) error {
	if education == nil {
		return fmt.Errorf("%w: education cannot be nil", ErrInvalidEducationData)
	}

	if id == uuid.Nil {
		return fmt.Errorf("%w: education ID cannot be nil", ErrInvalidEducationData)
	}

	// Sanitize and validate
	education.BeforeSave()
	if err := education.Validate(); err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidEducationData, err)
	}

	query := `
       UPDATE education
       SET institution = $1, location = $2, degree = $3, field = $4,
           start_date = $5, end_date = $6, description = $7, updated_at = $8
       WHERE id = $9`

	now := time.Now().UTC()
	startDate, endDate := r.parseEducationDates(education)

	result, err := r.db.ExecContext(
		ctx, query,
		education.Institution, education.Location, education.Degree,
		education.Field, startDate, endDate, education.Description, now, id,
	)

	if err != nil {
		log.Error().
			Err(err).
			Str("education_id", id.String()).
			Msg("failed to update education")
		return fmt.Errorf("%w: %v", ErrDatabaseOperation, err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		log.Error().
			Err(err).
			Str("education_id", id.String()).
			Msg("failed to get rows affected for update education")
		return fmt.Errorf("%w: %v", ErrDatabaseOperation, err)
	}

	if rowsAffected == 0 {
		return ErrEducationNotFound
	}

	log.Debug().
		Str("education_id", id.String()).
		Msg("education updated successfully")

	return nil
}

// DeleteEducation removes an education entry by ID
func (r *postgresEduRepository) DeleteEducation(ctx context.Context, id uuid.UUID) error {
	if id == uuid.Nil {
		return fmt.Errorf("%w: education ID cannot be nil", ErrInvalidEducationData)
	}

	query := `DELETE FROM education WHERE id = $1`

	result, err := r.db.ExecContext(ctx, query, id)
	if err != nil {
		log.Error().
			Err(err).
			Str("education_id", id.String()).
			Msg("failed to delete education")
		return fmt.Errorf("%w: %v", ErrDatabaseOperation, err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		log.Error().
			Err(err).
			Str("education_id", id.String()).
			Msg("failed to get rows affected for delete education")
		return fmt.Errorf("%w: %v", ErrDatabaseOperation, err)
	}

	if rowsAffected == 0 {
		return ErrEducationNotFound
	}

	log.Debug().
		Str("education_id", id.String()).
		Msg("education deleted successfully")

	return nil
}

// GetEducation retrieves a single education entry by ID
func (r *postgresEduRepository) GetEducation(ctx context.Context, id uuid.UUID) (*domain.Education, error) {
	if id == uuid.Nil {
		return nil, fmt.Errorf("%w: education ID cannot be nil", ErrInvalidEducationData)
	}

	query := `
		SELECT id, resume_id, institution, location, degree, field, 
			   start_date, end_date, description, created_at, updated_at
       FROM education
       WHERE id = $1`

	var row educationRow
	err := r.db.QueryRowContext(ctx, query, id).Scan(
		&row.ID, &row.ResumeID, &row.Institution, &row.Location,
		&row.Degree, &row.Field, &row.StartDate, &row.EndDate,
		&row.Description, &row.CreatedAt, &row.UpdatedAt,
	)

	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrEducationNotFound
		}
		log.Error().
			Err(err).
			Str("education_id", id.String()).
			Msg("failed to get education")
		return nil, fmt.Errorf("%w: %v", ErrDatabaseOperation, err)
	}

	return r.mapToEducationDomain(&row), nil
}

// GetEducationsByResumeID retrieves all education entries for a resume
func (r *postgresEduRepository) GetEducationsByResumeID(ctx context.Context, resumeID uuid.UUID) ([]*domain.Education, error) {
	if resumeID == uuid.Nil {
		return nil, fmt.Errorf("%w: resume ID cannot be nil", ErrInvalidEducationData)
	}

	query := `
		SELECT id, resume_id, institution, location, degree, field, 
			   start_date, end_date, description, created_at, updated_at
		FROM education
		WHERE resume_id = $1
		ORDER BY start_date DESC`

	rows, err := r.db.QueryContext(ctx, query, resumeID)
	if err != nil {
		log.Error().
			Err(err).
			Str("resume_id", resumeID.String()).
			Msg("failed to get educations by resume ID")
		return nil, fmt.Errorf("%w: %v", ErrDatabaseOperation, err)
	}
	defer rows.Close()

	var educations []*domain.Education
	for rows.Next() {
		var row educationRow
		err := rows.Scan(
			&row.ID, &row.ResumeID, &row.Institution, &row.Location,
			&row.Degree, &row.Field, &row.StartDate, &row.EndDate,
			&row.Description, &row.CreatedAt, &row.UpdatedAt,
		)
		if err != nil {
			log.Error().
				Err(err).
				Str("resume_id", resumeID.String()).
				Msg("failed to scan education row")
			return nil, fmt.Errorf("%w: %v", ErrDatabaseOperation, err)
		}
		educations = append(educations, r.mapToEducationDomain(&row))
	}

	if err := rows.Err(); err != nil {
		log.Error().
			Err(err).
			Str("resume_id", resumeID.String()).
			Msg("error iterating education rows")
		return nil, fmt.Errorf("%w: %v", ErrDatabaseOperation, err)
	}

	return educations, nil
}

// DeleteEducationsByResumeID removes all education entries for a resume
func (r *postgresEduRepository) DeleteEducationsByResumeID(ctx context.Context, resumeID uuid.UUID) error {
	if resumeID == uuid.Nil {
		return fmt.Errorf("%w: resume ID cannot be nil", ErrInvalidEducationData)
	}

	query := `DELETE FROM education WHERE resume_id = $1`

	result, err := r.db.ExecContext(ctx, query, resumeID)
	if err != nil {
		log.Error().
			Err(err).
			Str("resume_id", resumeID.String()).
			Msg("failed to delete educations by resume ID")
		return fmt.Errorf("%w: %v", ErrDatabaseOperation, err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		log.Error().
			Err(err).
			Str("resume_id", resumeID.String()).
			Msg("failed to get rows affected for delete educations")
		return fmt.Errorf("%w: %v", ErrDatabaseOperation, err)
	}

	log.Debug().
		Str("resume_id", resumeID.String()).
		Int64("deleted_count", rowsAffected).
		Msg("educations deleted successfully")

	return nil
}

// CountByResumeID returns the number of education entries for a resume
func (r *postgresEduRepository) CountByResumeID(ctx context.Context, resumeID uuid.UUID) (int, error) {
	if resumeID == uuid.Nil {
		return 0, fmt.Errorf("%w: resume ID cannot be nil", ErrInvalidEducationData)
	}

	query := `SELECT COUNT(*) FROM education WHERE resume_id = $1`

	var count int
	err := r.db.QueryRowContext(ctx, query, resumeID).Scan(&count)
	if err != nil {
		log.Error().
			Err(err).
			Str("resume_id", resumeID.String()).
			Msg("failed to count educations by resume ID")
		return 0, fmt.Errorf("%w: %v", ErrDatabaseOperation, err)
	}

	return count, nil
}

// AddEducationsBatch adds multiple education entries in a transaction
func (r *postgresEduRepository) AddEducationsBatch(ctx context.Context, resumeID uuid.UUID, educations []*domain.Education) ([]uuid.UUID, error) {
	if resumeID == uuid.Nil {
		return nil, fmt.Errorf("%w: resume ID cannot be nil", ErrInvalidEducationData)
	}

	if len(educations) == 0 {
		return []uuid.UUID{}, nil
	}

	// Validate all educations first
	for i, edu := range educations {
		if edu == nil {
			return nil, fmt.Errorf("%w: education at index %d is nil", ErrInvalidEducationData, i)
		}
		edu.BeforeSave()
		if err := edu.Validate(); err != nil {
			return nil, fmt.Errorf("%w: education at index %d: %v", ErrInvalidEducationData, i, err)
		}
	}

	// Start transaction
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		log.Error().
			Err(err).
			Str("resume_id", resumeID.String()).
			Msg("failed to begin transaction for batch add educations")
		return nil, fmt.Errorf("%w: failed to begin transaction: %v", ErrDatabaseOperation, err)
	}
	defer func() {
		if err != nil {
			_ = tx.Rollback()
		}
	}()

	query := `
		INSERT INTO education (
			id, resume_id, institution, location, degree, field, 
			start_date, end_date, description, created_at, updated_at
		)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
		RETURNING id`

	stmt, err := tx.PrepareContext(ctx, query)
	if err != nil {
		log.Error().
			Err(err).
			Str("resume_id", resumeID.String()).
			Msg("failed to prepare statement for batch add educations")
		return nil, fmt.Errorf("%w: failed to prepare statement: %v", ErrDatabaseOperation, err)
	}
	defer stmt.Close()

	now := time.Now().UTC()
	ids := make([]uuid.UUID, 0, len(educations))

	for i, edu := range educations {
		id := uuid.New()
		startDate, endDate := r.parseEducationDates(edu)

		var returnedID uuid.UUID
		err = stmt.QueryRowContext(
			ctx,
			id, resumeID, edu.Institution, edu.Location,
			edu.Degree, edu.Field, startDate, endDate,
			edu.Description, now, now,
		).Scan(&returnedID)

		if err != nil {
			log.Error().
				Err(err).
				Str("resume_id", resumeID.String()).
				Int("index", i).
				Msg("failed to insert education in batch")
			return nil, fmt.Errorf("%w: failed to insert education at index %d: %v", ErrDatabaseOperation, i, err)
		}

		ids = append(ids, returnedID)
	}

	if err = tx.Commit(); err != nil {
		log.Error().
			Err(err).
			Str("resume_id", resumeID.String()).
			Msg("failed to commit transaction for batch add educations")
		return nil, fmt.Errorf("%w: failed to commit transaction: %v", ErrDatabaseOperation, err)
	}

	log.Debug().
		Str("resume_id", resumeID.String()).
		Int("count", len(ids)).
		Msg("batch educations added successfully")

	return ids, nil
}

// ExistsForResume checks if an education entry exists for a given resume
func (r *postgresEduRepository) ExistsForResume(ctx context.Context, educationID, resumeID uuid.UUID) (bool, error) {
	if educationID == uuid.Nil || resumeID == uuid.Nil {
		return false, fmt.Errorf("%w: education ID and resume ID cannot be nil", ErrInvalidEducationData)
	}

	query := `SELECT EXISTS(SELECT 1 FROM education WHERE id = $1 AND resume_id = $2)`

	var exists bool
	err := r.db.QueryRowContext(ctx, query, educationID, resumeID).Scan(&exists)
	if err != nil {
		log.Error().
			Err(err).
			Str("education_id", educationID.String()).
			Str("resume_id", resumeID.String()).
			Msg("failed to check if education exists for resume")
		return false, fmt.Errorf("%w: %v", ErrDatabaseOperation, err)
	}

	return exists, nil
}

// Helper types for database row mapping

type educationRow struct {
	ID          uuid.UUID
	ResumeID    uuid.UUID
	Institution string
	Location    sql.NullString
	Degree      string
	Field       sql.NullString
	StartDate   time.Time
	EndDate     *time.Time
	Description sql.NullString
	CreatedAt   time.Time
	UpdatedAt   time.Time
}

// mapToEducationDomain converts a database row to domain Education
func (r *postgresEduRepository) mapToEducationDomain(row *educationRow) *domain.Education {
	startDate := row.StartDate.Format(dateFormat)
	endDate := "Present"
	if row.EndDate != nil {
		endDate = row.EndDate.Format(dateFormat)
	}

	return &domain.Education{
		Institution: row.Institution,
		Location:    nullStringToString(row.Location),
		Degree:      row.Degree,
		Field:       nullStringToString(row.Field),
		StartDate:   startDate,
		EndDate:     endDate,
		Description: nullStringToString(row.Description),
	}
}

// parseEducationDates converts domain date strings to time.Time pointers
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

// nullStringToString safely converts sql.NullString to string
func nullStringToString(ns sql.NullString) string {
	if ns.Valid {
		return ns.String
	}
	return ""
}
