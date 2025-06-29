package domain

import (
	"context"
	"github.com/google/uuid"
)

type EducationRepository interface {
	AddEducation(ctx context.Context, resumeId uuid.UUID, education *Education) (uuid.UUID, error)
	UpdateEducation(ctx context.Context, id uuid.UUID, education *Education) error
	DeleteEducation(ctx context.Context, id uuid.UUID) error
	GetEducation(ctx context.Context, id uuid.UUID) (*Education, error)
}

type ExperienceRepository interface {
	AddExperience(ctx context.Context, resumeId uuid.UUID, experience *Experience) (uuid.UUID, error)
	UpdateExperience(ctx context.Context, id uuid.UUID, experience *Experience) error
	DeleteExperience(ctx context.Context, id uuid.UUID) error
	GetExperience(ctx context.Context, id uuid.UUID) (*Experience, error)
	GetExperienceByResume(ctx context.Context, resumeId string) ([]*Experience, error)
}

type SkillRepository interface {
	Create(ctx context.Context, skill *Skill) error
	GetByID(ctx context.Context, id uuid.UUID) (*Skill, error)
	GetByUserID(ctx context.Context, userID uuid.UUID) ([]*Skill, error)
	GetByUserIDAndCategory(ctx context.Context, userID uuid.UUID, category string) ([]*Skill, error)
	Update(ctx context.Context, skill *Skill) error
	Delete(ctx context.Context, id uuid.UUID) error
	DeleteByUserID(ctx context.Context, userID uuid.UUID) error
	CountByUserID(ctx context.Context, userID uuid.UUID) (int, error)
	GetCategoriesByUserID(ctx context.Context, userID uuid.UUID) ([]string, error)
}
