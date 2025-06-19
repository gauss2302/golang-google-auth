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
