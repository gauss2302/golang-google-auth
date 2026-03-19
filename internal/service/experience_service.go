package service

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"googleAuth/internal/domain"
	"googleAuth/internal/domain/dto"

	"github.com/google/uuid"
)

// ExperienceService defines the interface for experience operations
type ExperienceService interface {
	AddExperience(ctx context.Context, resumeID uuid.UUID, req *dto.ExperienceCreateRequest) (*domain.Experience, error)
	UpdateExperience(ctx context.Context, experienceID uuid.UUID, req *dto.ExperienceUpdateRequest) (*domain.Experience, error)
	GetExperience(ctx context.Context, experienceID uuid.UUID) (*domain.Experience, error)
	GetExperiencesByResume(ctx context.Context, resumeID string) ([]*domain.Experience, error)
	DeleteExperience(ctx context.Context, experienceID uuid.UUID) error
}

type experienceService struct {
	expRepo domain.ExperienceRepository
}

// NewExperienceService creates a new experience service
func NewExperienceService(expRepo domain.ExperienceRepository) ExperienceService {
	if expRepo == nil {
		panic("experience repository is required for experience service")
	}
	return &experienceService{
		expRepo: expRepo,
	}
}

// AddExperience creates a new experience entry for a resume
func (s *experienceService) AddExperience(ctx context.Context, resumeID uuid.UUID, req *dto.ExperienceCreateRequest) (*domain.Experience, error) {
	if err := s.validateCreateRequest(req); err != nil {
		return nil, fmt.Errorf("validation failed: %w", err)
	}

	if resumeID == uuid.Nil {
		return nil, errors.New("resume ID cannot be nil")
	}

	experience := req.ToExperience()

	experienceID, err := s.expRepo.AddExperience(ctx, resumeID, experience)
	if err != nil {
		return nil, fmt.Errorf("failed to add experience: %w", err)
	}

	// Fetch the created experience to return complete data
	createdExperience, err := s.expRepo.GetExperience(ctx, experienceID)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch created experience: %w", err)
	}

	return createdExperience, nil
}

// UpdateExperience updates an existing experience entry
func (s *experienceService) UpdateExperience(ctx context.Context, experienceID uuid.UUID, req *dto.ExperienceUpdateRequest) (*domain.Experience, error) {
	if err := s.validateUpdateRequest(req); err != nil {
		return nil, fmt.Errorf("validation failed: %w", err)
	}

	if experienceID == uuid.Nil {
		return nil, errors.New("experience ID cannot be nil")
	}

	// Check if experience exists
	existingExperience, err := s.expRepo.GetExperience(ctx, experienceID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, errors.New("experience not found")
		}
		return nil, fmt.Errorf("failed to check existing experience: %w", err)
	}
	if existingExperience == nil {
		return nil, errors.New("experience not found")
	}

	// Apply updates
	req.ApplyTo(existingExperience)

	// Update in repository
	err = s.expRepo.UpdateExperience(ctx, experienceID, existingExperience)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, errors.New("experience not found")
		}
		return nil, fmt.Errorf("failed to update experience: %w", err)
	}

	// Fetch updated experience
	result, err := s.expRepo.GetExperience(ctx, experienceID)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch updated experience: %w", err)
	}

	return result, nil
}

// GetExperience retrieves a single experience entry by ID
func (s *experienceService) GetExperience(ctx context.Context, experienceID uuid.UUID) (*domain.Experience, error) {
	if experienceID == uuid.Nil {
		return nil, errors.New("invalid experience ID")
	}

	experience, err := s.expRepo.GetExperience(ctx, experienceID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, errors.New("experience not found")
		}
		return nil, fmt.Errorf("failed to get experience: %w", err)
	}

	if experience == nil {
		return nil, errors.New("experience not found")
	}

	return experience, nil
}

// GetExperiencesByResume retrieves all experience entries for a resume
func (s *experienceService) GetExperiencesByResume(ctx context.Context, resumeID string) ([]*domain.Experience, error) {
	if resumeID == "" {
		return nil, errors.New("resume ID is required")
	}

	experiences, err := s.expRepo.GetExperienceByResume(ctx, resumeID)
	if err != nil {
		return nil, fmt.Errorf("failed to get experiences by resume: %w", err)
	}

	return experiences, nil
}

// DeleteExperience removes an experience entry by ID
func (s *experienceService) DeleteExperience(ctx context.Context, experienceID uuid.UUID) error {
	if experienceID == uuid.Nil {
		return errors.New("invalid experience ID")
	}

	// Check if experience exists
	experience, err := s.expRepo.GetExperience(ctx, experienceID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return errors.New("experience not found")
		}
		return fmt.Errorf("failed to check experience existence: %w", err)
	}
	if experience == nil {
		return errors.New("experience not found")
	}

	err = s.expRepo.DeleteExperience(ctx, experienceID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return errors.New("experience not found")
		}
		return fmt.Errorf("failed to delete experience: %w", err)
	}

	return nil
}

// Validation helpers

func (s *experienceService) validateCreateRequest(req *dto.ExperienceCreateRequest) error {
	if req == nil {
		return errors.New("request cannot be nil")
	}
	if req.Employer == "" {
		return errors.New("employer is required")
	}
	if req.JobTitle == "" {
		return errors.New("job title is required")
	}
	if req.StartDate == "" {
		return errors.New("start date is required")
	}
	return nil
}

func (s *experienceService) validateUpdateRequest(req *dto.ExperienceUpdateRequest) error {
	if req == nil {
		return errors.New("request cannot be nil")
	}
	// At least one field must be provided for update
	if req.Employer == nil && req.JobTitle == nil && req.Location == nil &&
		req.StartDate == nil && req.EndDate == nil && req.Description == nil &&
		req.Achievements == nil {
		return errors.New("at least one field must be provided for update")
	}
	return nil
}

