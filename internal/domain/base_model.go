package domain

import "time"

// BaseModel provides a set of common fields that are embedded in other domain models.
// This promotes consistency and reduces redundancy across different entities.
// By embedding this struct, other models automatically inherit these fields.
type BaseModel struct {
	CreatedAt time.Time  // Timestamp indicating when the record was created.
	UpdatedAt time.Time  // Timestamp of the last update to the record.
	DeletedAt *time.Time // Pointer to a time, used for soft deletion. If nil, the record is not deleted.
}
