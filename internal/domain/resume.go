package domain

import (
	"github.com/google/uuid"
	"time"
)

type Resume struct {
	ID        uuid.UUID `json:"id" db:"cv_id"`
	UserID    uuid.UUID `json:"user_id" db:"did"`
	CreatedAt time.Time `json:"created_at" db:"created_at"`
	UpdatedAt time.Time `json:"updated_at" db:"updated_at"`

	Education []*Education `json:"education,omitempty" db:"-"`
}

//type ResumeRepository interface {
//	AddEducation(ctx context.Context, resumeID uuid.UUID, education *Education) (uuid.UUID, error)
//	UpdateEducation(ctx context.Context, id uuid.UUID, education *Education) error
//	DeleteEducation(ctx context.Context, id uuid.UUID) error
//	GetEducation(ctx context.Context, id uuid.UUID) (*Education, error)
//	GetEducationByResume(ctx context.Context, resumeID uuid.UUID) ([]*Education, error)
//}
