package dto

import (
	"github.com/google/uuid"
	"googleAuth/internal/domain"
)

// ExperienceCreateRequest represents a request to create a new experience entry
type ExperienceCreateRequest struct {
	Employer     string   `json:"employer" validate:"required,max=200"`
	JobTitle     string   `json:"job_title" validate:"required,max=200"`
	Location     string   `json:"location" validate:"omitempty,max=200"`
	StartDate    string   `json:"start_date" validate:"required,datetime=2006-01-02"`
	EndDate      string   `json:"end_date" validate:"omitempty,date_or_present"`
	Description  string   `json:"description" validate:"omitempty,max=2000"`
	Achievements []string `json:"achievements,omitempty" validate:"max=20,dive,max=500"`
}

// ExperienceUpdateRequest represents a request to update an existing experience entry
type ExperienceUpdateRequest struct {
	Employer     *string   `json:"employer,omitempty" validate:"omitempty,max=200"`
	JobTitle     *string   `json:"job_title,omitempty" validate:"omitempty,max=200"`
	Location     *string   `json:"location,omitempty" validate:"omitempty,max=200"`
	StartDate    *string   `json:"start_date,omitempty" validate:"omitempty,datetime=2006-01-02"`
	EndDate      *string   `json:"end_date,omitempty" validate:"omitempty,date_or_present"`
	Description  *string   `json:"description,omitempty" validate:"omitempty,max=2000"`
	Achievements *[]string `json:"achievements,omitempty" validate:"omitempty,max=20,dive,max=500"`
}

// ToExperience converts ExperienceCreateRequest to domain Experience
func (req *ExperienceCreateRequest) ToExperience() *domain.Experience {
	return &domain.Experience{
		Employer:     req.Employer,
		JobTitle:     req.JobTitle,
		Location:     req.Location,
		StartDate:    req.StartDate,
		EndDate:      req.EndDate,
		Description:  req.Description,
		Achievements: req.Achievements,
	}
}

// ApplyTo applies updates from ExperienceUpdateRequest to existing domain Experience
// Only updates fields that were provided in the request (not nil)
func (req *ExperienceUpdateRequest) ApplyTo(experience *domain.Experience) {
	if req.Employer != nil {
		experience.Employer = *req.Employer
	}
	if req.JobTitle != nil {
		experience.JobTitle = *req.JobTitle
	}
	if req.Location != nil {
		experience.Location = *req.Location
	}
	if req.StartDate != nil {
		experience.StartDate = *req.StartDate
	}
	if req.EndDate != nil {
		experience.EndDate = *req.EndDate
	}
	if req.Description != nil {
		experience.Description = *req.Description
	}
	if req.Achievements != nil {
		experience.Achievements = *req.Achievements
	}
}

// ExperienceResponse represents the API response for an experience entry
type ExperienceResponse struct {
	ID           uuid.UUID `json:"id"`
	ResumeID     uuid.UUID `json:"resume_id"`
	Employer     string    `json:"employer"`
	JobTitle     string    `json:"job_title"`
	Location     string    `json:"location"`
	StartDate    string    `json:"start_date"`
	EndDate      string    `json:"end_date"`
	Description  string    `json:"description"`
	Achievements []string  `json:"achievements"`
	CreatedAt    string    `json:"created_at,omitempty"`
	UpdatedAt    string    `json:"updated_at,omitempty"`
}

