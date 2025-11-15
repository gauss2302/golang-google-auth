package repository

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"googleAuth/internal/domain"
	"time"

	"github.com/google/uuid"
	"github.com/rs/zerolog/log"
)

type postgresJobRepository struct {
	db *sql.DB
}

func (j *postgresJobRepository) NewJobRepository(db *sql.DB) domain.JobRepository {
	return &postgresJobRepository{db: db}
}

func (j *postgresJobRepository) CreatePosition(ctx context.Context, jobId uuid.UUID, headHunterId uuid.UUID, jobPosition *domain.JobPosition) (uuid.UUID, error) {
	query := `INSERT into position (
                      id, slug, company_id, company_name, hunter_id, 
                      title, description, summary, 
                      job_type, work_arrangment, experience_level, 
                      department, category, seniority, location,
                      requirements, benefits, created_at, updated_at)
    VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19)
    RETURNING id`

	id := uuid.New()
	now := time.Now()

	var returnedId uuid.UUID

	err := j.db.QueryRowContext(ctx, query, id, jobPosition.Slug, jobPosition.CompanyID, jobPosition.Company, headHunterId,
		jobPosition.Title, jobPosition.Description, jobPosition.Summary, jobPosition.JobType, jobPosition.WorkArrangement,
		jobPosition.ExperienceLevel, jobPosition.Department, jobPosition.Category, jobPosition.Seniority, jobPosition.Location,
		jobPosition.Requirements, jobPosition.Benefits, now, now).Scan(&returnedId)

	if err != nil {
		log.Error().Err(err).Msg("failed to add education")
		return uuid.Nil, err
	}

	return returnedId, nil
}

func (j *postgresJobRepository) UpdatePosition(ctx context.Context, jobId uuid.UUID, jobPosition *domain.JobPosition) error {
	query := `UPDATE position
	SET title = $1, description = $2, summary = $3, job_type = $4, work_arrangment = $5,
	    experience_level = $6, department = $7, category = $8, seniority = $9, location = $10,
		requirements = $11, benefits = $12, updated_at = $13,
		WHERE id = $14`

	now := time.Now()
	result, err := j.db.ExecContext(ctx, query, jobPosition.Title, jobPosition.Description, jobPosition.Summary, jobPosition.JobType,
		jobPosition.WorkArrangement, jobPosition.ExperienceLevel, jobPosition.Department, jobPosition.Category, jobPosition.Seniority,
		jobPosition.Location, jobPosition.Requirements, jobPosition.Benefits, now, jobId)

	if err != nil {
		log.Error().Err(err).Msg("failed to update job position")
		return err
	}

	return j.checkRowsAffected(result, "update job position")
}

func (j *postgresJobRepository) GetByPositionId(ctx context.Context, jobId uuid.UUID) (*domain.JobPosition, error) {
	jobPosition := &domain.JobPosition{}

	query := `
		SELECT  id, slug, company_id, company_name, hunter_id, 
                      title, description, summary, 
                      job_type, work_arrangment, experience_level, 
                      department, category, seniority, location,
                      requirements, benefits, created_at, updated_at
			FROM position WHERE id = $1
		`

	err := j.db.QueryRowContext(ctx, query, jobId).Scan(
		&jobPosition.ID, &jobPosition.Slug, &jobPosition.CompanyID, &jobPosition.Company, &jobPosition.HunterID,
		&jobPosition.Title, &jobPosition.Description, &jobPosition.Summary, &jobPosition.JobType, &jobPosition.WorkArrangement,
		&jobPosition.ExperienceLevel, &jobPosition.Department, &jobPosition.Category, &jobPosition.Seniority, &jobPosition.Location,
		&jobPosition.Requirements, &jobPosition.Benefits, &jobPosition.CreatedAt, &jobPosition.UpdatedAt)

	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}

	return jobPosition, nil
}

func (j *postgresJobRepository) GetByCategory(ctx context.Context, category string, offset, limit int) ([]*domain.JobPosition, error) {
	if limit <= 0 || limit > 100 {
		limit = 20 // default limit with max cap
	}
	if offset < 0 {
		offset = 0
	}

	jobPositions := make([]*domain.JobPosition, 0)

	query := `
        SELECT id, slug, company_id, company_name, hunter_id, 
               title, description, summary, 
               job_type, work_arrangment, experience_level, 
               department, category, seniority, location,
               requirements, benefits, created_at, updated_at
        FROM position 
        WHERE category = $1
        ORDER BY created_at DESC
        LIMIT $2 OFFSET $3
    `

	rows, err := j.db.QueryContext(ctx, query, category, limit, offset)
	if err != nil {
		return nil, fmt.Errorf("failed to query jobs by category: %w", err)
	}
	defer rows.Close()

	for rows.Next() {
		jobPosition := &domain.JobPosition{}

		err := rows.Scan(
			&jobPosition.ID, &jobPosition.Slug, &jobPosition.CompanyID, &jobPosition.Company, &jobPosition.HunterID,
			&jobPosition.Title, &jobPosition.Description, &jobPosition.Summary, &jobPosition.JobType, &jobPosition.WorkArrangement,
			&jobPosition.ExperienceLevel, &jobPosition.Department, &jobPosition.Category, &jobPosition.Seniority, &jobPosition.Location,
			&jobPosition.Requirements, &jobPosition.Benefits, &jobPosition.CreatedAt, &jobPosition.UpdatedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan job position: %w", err)
		}

		jobPositions = append(jobPositions, jobPosition)
	}

	if err = rows.Err(); err != nil {
		return nil, fmt.Errorf("row iteration error: %w", err)
	}

	return jobPositions, nil
}

func (j *postgresJobRepository) DeletePosition(ctx context.Context, jobId uuid.UUID) error {
	query := `DELETE FROM position WHERE id = $1`

	result, err := j.db.ExecContext(ctx, query, jobId)
	if err != nil {
		log.Error().Err(err).Msg("failed to delete job position")
		return err
	}

	return j.checkRowsAffected(result, "delete job position")
}

func (j *postgresJobRepository) DeleteThisPosition(ctx context.Context, jobId uuid.UUID) error {
	query := `DELETE FROM position WHERE id = $1`

	_, err := j.db.ExecContext(ctx, query, jobId)
	if err != nil {
			log.Error().Err(err).Msg("failed to delete job position")
		return err
	}

	return nil
}

func (j *postgresJobRepository) checkRowsAffected(result sql.Result, operation string) error {
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
