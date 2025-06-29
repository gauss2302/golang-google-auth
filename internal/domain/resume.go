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
