package service

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"github.com/google/uuid"
	"googleAuth/internal/domain"
	"googleAuth/internal/domain/dto"
)

type JobService interface {
	CreatePosition(ctx context.Context, headHunterId, companyId uuid.UUID, req *dto.JobCreateRequest) (*domain.JobPosition, error)
	UpdatePosition(ctx context.Context, jobId uuid.UUID, req *dto.JobUpdateRequest) (*domain.JobPosition, error)
	GetPositionById(ctx context.Context, jobId uuid.UUID) (*domain.JobPosition, error)
	GetPositionsByCategory(ctx context.Context, req *dto.JobFilterRequest) ([]*domain.JobPosition, error)
	DeletePosition(ctx context.Context, jobId uuid.UUID) error
}

type jobService struct {
	jobRepo domain.JobRepository
}

func NewJobService(jobRepo domain.JobRepository) JobService {
	return &jobService{jobRepo: jobRepo}
}

func (j *jobService) CreatePosition(ctx context.Context, headHunterId, companyId uuid.UUID, req *dto.JobCreateRequest) (*domain.JobPosition, error) {
	if err := j.validateCreateRequest(req); err != nil {
		return nil, fmt.Errorf("validation failed: %w", err)
	}

	jobPosition := &domain.JobPosition{
		Slug:        req.Slug,
		CompanyID:   companyId,
		Title:       req.Title,
		Description: req.Description,
		Summary:     req.Summary,
		Department:  req.Department,
		Category:    req.Category,
		Seniority:   req.Seniority,
	}

	jobId, err := j.jobRepo.CreatePosition(ctx, uuid.New(), headHunterId, jobPosition)
	if err != nil {
		return nil, fmt.Errorf("failed to create position: %w", err)
	}

	// Fetch the created position to return complete data
	createdPosition, err := j.jobRepo.GetByPositionId(ctx, jobId)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch created position: %w", err)
	}

	return createdPosition, nil
}

func (j *jobService) UpdatePosition(ctx context.Context, jobId uuid.UUID, req *dto.JobUpdateRequest) (*domain.JobPosition, error) {
	if err := j.validateUpdateRequest(req); err != nil {
		return nil, fmt.Errorf("validation failed: %w", err)
	}

	// Check if position exists
	existingPosition, err := j.jobRepo.GetByPositionId(ctx, jobId)
	if err != nil {
		return nil, fmt.Errorf("failed to check existing position: %w", err)
	}
	if existingPosition == nil {
		return nil, errors.New("position not found")
	}

	// Update position with new data
	updatedPosition := &domain.JobPosition{
		Title:           req.Title,
		Description:     req.Description,
		Summary:         req.Summary,
		JobType:         domain.JobType(req.JobType),
		WorkArrangement: domain.WorkArrangement(req.WorkArrangement),
		ExperienceLevel: domain.ExperienceLevel(req.ExperienceLevel),
		Department:      req.Department,
		Category:        req.Category,
		Seniority:       req.Seniority,
	}

	err = j.jobRepo.UpdatePosition(ctx, jobId, updatedPosition)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, errors.New("position not found")
		}
		return nil, fmt.Errorf("failed to update position: %w", err)
	}

	// Fetch updated position
	result, err := j.jobRepo.GetByPositionId(ctx, jobId)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch updated position: %w", err)
	}

	return result, nil
}

func (j *jobService) GetPositionById(ctx context.Context, jobId uuid.UUID) (*domain.JobPosition, error) {
	if jobId == uuid.Nil {
		return nil, errors.New("invalid job ID")
	}

	position, err := j.jobRepo.GetByPositionId(ctx, jobId)
	if err != nil {
		return nil, fmt.Errorf("failed to get position: %w", err)
	}

	if position == nil {
		return nil, errors.New("position not found")
	}

	return position, nil
}

func (j *jobService) GetPositionsByCategory(ctx context.Context, req *dto.JobFilterRequest) ([]*domain.JobPosition, error) {
	if req.Category == "" {
		return nil, errors.New("category is required")
	}

	// Set defaults if not provided
	if req.Limit <= 0 {
		req.Limit = 20
	}
	if req.Offset < 0 {
		req.Offset = 0
	}

	positions, err := j.jobRepo.GetByCategory(ctx, req.Category, req.Offset, req.Limit)
	if err != nil {
		return nil, fmt.Errorf("failed to get positions by category: %w", err)
	}

	return positions, nil
}

func (j *jobService) DeletePosition(ctx context.Context, jobId uuid.UUID) error {
	if jobId == uuid.Nil {
		return errors.New("invalid job ID")
	}

	// Check if position exists
	position, err := j.jobRepo.GetByPositionId(ctx, jobId)
	if err != nil {
		return fmt.Errorf("failed to check position existence: %w", err)
	}
	if position == nil {
		return errors.New("position not found")
	}

	err = j.jobRepo.DeletePosition(ctx, jobId)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return errors.New("position not found")
		}
		return fmt.Errorf("failed to delete position: %w", err)
	}

	return nil
}

// Validation helpers
func (j *jobService) validateCreateRequest(req *dto.JobCreateRequest) error {
	if req.Slug == "" {
		return errors.New("slug is required")
	}
	if req.CompanyName == "" {
		return errors.New("company name is required")
	}
	if req.Title == "" {
		return errors.New("title is required")
	}
	if req.Description == "" {
		return errors.New("description is required")
	}
	if req.Category == "" {
		return errors.New("category is required")
	}
	if req.Location == "" {
		return errors.New("location is required")
	}
	return nil
}

func (j *jobService) validateUpdateRequest(req *dto.JobUpdateRequest) error {
	if req.Title == "" {
		return errors.New("title is required")
	}
	if req.Description == "" {
		return errors.New("description is required")
	}
	if req.Category == "" {
		return errors.New("category is required")
	}
	if req.Location == "" {
		return errors.New("location is required")
	}
	return nil
}
