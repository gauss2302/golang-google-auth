package domain

import (
	"context"
	"github.com/google/uuid"
)

type JobRepository interface {
	CreatePosition(ctx context.Context, jobId uuid.UUID, headHunterId uuid.UUID, jobPosition *JobPosition) error
	UpdatePosition(ctx context.Context, jobId uuid.UUID, jobPosition *JobPosition) error
}
