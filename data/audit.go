package data

import (
	"time"

	"github.com/google/uuid"
)

// Audit represents Audit Record capturing record of events, activities or transactions that happened
// for the application
//
// swagger:model
type Audit struct {
	ID        int       `json:"id" gorm:"primaryKey"`
	CreatedAt time.Time `json:"createdat" gorm:"autoCreateTime;index;not null"`

	ApplicationID uuid.UUID `json:"aplicationid" gorm:"not null;index;constraint:OnUpdate:CASCADE,OnDelete:CASCADE"`

	Action ActionTypeEnum `json:"action" gorm:"not null;index"`

	UserID uuid.UUID `json:"userid" validate:"required" gorm:"index;not null"`

	Status ActionStatusTypeEnum `json:"status" validate:"required" gorm:"index;not null"`

	Details string `json:"details" validate:"required"`
}
