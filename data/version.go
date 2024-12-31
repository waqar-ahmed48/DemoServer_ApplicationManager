package data

import (
	"time"

	"github.com/google/uuid"
)

// Version represents different version of application resources
//
// swagger:model
type Version struct {
	ID        int       `json:"id" gorm:"primaryKey"`
	CreatedAt time.Time `json:"createdat" gorm:"autoCreateTime;index;not null"`
	UpdatedAt time.Time `json:"updatedat" gorm:"autoUpdateTime;index"`

	// User friendly name for Application
	// required: true
	Name string `json:"name" validate:"required" gorm:"index;not null;unique"`

	// Description of Application
	// required: false
	Description string `json:"description" gorm:"index"`

	ApplicationID uuid.UUID `json:"aplicationid" gorm:"not null;index;constraint:OnUpdate:CASCADE,OnDelete:CASCADE"`

	State VersionStateTypeEnum `json:"state" gorm:"index;not null"`

	UsageCounter int       `json:"usage_counter"`
	LastUsed     time.Time `json:"last_used"`
}
