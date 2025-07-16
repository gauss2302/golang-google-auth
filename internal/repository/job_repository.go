package repository

import (
	"context"
	"database/sql"
	"github.com/google/uuid"
	"googleAuth/internal/domain"
)

type postgresJobRepository struct {
	db *sql.DB
}

func (j *postgresJobRepository) NewJobRepository(db *sql.DB) domain.JobRepository {
	return &postgresJobRepository{db: db}
}

func (j *postgresJobRepository) CreatePosition(ctx context.Context, jobId uuid.UUID, headHunterId uuid.UUID, jobPosition *domain.JobPosition) error {

	panic("implement me")
}

func (j *postgresJobRepository) UpdatePosition(ctx context.Context, jobId uuid.UUID, jobPosition *domain.JobPosition) error {
	panic("implement me")
}
