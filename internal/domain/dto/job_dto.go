package dto

import "github.com/google/uuid"

type JobCreateRequest struct {
	Slug            string `json:"slug" validate:"required"`
	CompanyName     string `json:"company_name" validate:"required"`
	Title           string `json:"title" validate:"required"`
	Description     string `json:"description" validate:"required"`
	Summary         string `json:"summary"`
	JobType         string `json:"job_type" validate:"required"`
	WorkArrangement string `json:"work_arrangement" validate:"required"`
	ExperienceLevel string `json:"experience_level" validate:"required"`
	Department      string `json:"department" validate:"required"`
	Category        string `json:"category" validate:"required"`
	Seniority       string `json:"seniority" validate:"required"`
	Location        string `json:"location" validate:"required"`
	Requirements    string `json:"requirements"`
	Benefits        string `json:"benefits"`
}

type JobUpdateRequest struct {
	Title           string `json:"title" validate:"required"`
	Description     string `json:"description" validate:"required"`
	Summary         string `json:"summary"`
	JobType         string `json:"job_type" validate:"required"`
	WorkArrangement string `json:"work_arrangement" validate:"required"`
	ExperienceLevel string `json:"experience_level" validate:"required"`
	Department      string `json:"department" validate:"required"`
	Category        string `json:"category" validate:"required"`
	Seniority       string `json:"seniority" validate:"required"`
	Location        string `json:"location" validate:"required"`
	Requirements    string `json:"requirements"`
	Benefits        string `json:"benefits"`
}

type JobFilterRequest struct {
	Category string `json:"category" validate:"required"`
	Offset   int    `json:"offset"`
	Limit    int    `json:"limit"`
}

type JobResponse struct {
	ID              uuid.UUID `json:"id"`
	Slug            string    `json:"slug"`
	CompanyID       uuid.UUID `json:"company_id"`
	CompanyName     string    `json:"company_name"`
	HunterID        uuid.UUID `json:"hunter_id"`
	Title           string    `json:"title"`
	Description     string    `json:"description"`
	Summary         string    `json:"summary"`
	JobType         string    `json:"job_type"`
	WorkArrangement string    `json:"work_arrangement"`
	ExperienceLevel string    `json:"experience_level"`
	Department      string    `json:"department"`
	Category        string    `json:"category"`
	Seniority       string    `json:"seniority"`
	Location        string    `json:"location"`
	Requirements    string    `json:"requirements"`
	Benefits        string    `json:"benefits"`
	CreatedAt       string    `json:"created_at"`
	UpdatedAt       string    `json:"updated_at"`
}
