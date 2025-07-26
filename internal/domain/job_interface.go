package domain

import (
	"context"
	"github.com/google/uuid"
)

type JobRepository interface {
	CreatePosition(ctx context.Context, jobId uuid.UUID, headHunterId uuid.UUID, jobPosition *JobPosition) (uuid.UUID, error)
	UpdatePosition(ctx context.Context, jobId uuid.UUID, jobPosition *JobPosition) error
	DeletePosition(ctx context.Context, jobId uuid.UUID) error
	GetByPositionId(ctx context.Context, jobId uuid.UUID) (*JobPosition, error)
	GetByCategory(ctx context.Context, category string, offset, limit int) ([]*JobPosition, error)
}
