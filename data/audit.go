package data

import (
	"time"

	"github.com/google/uuid"
)

// AuditRecord represents schema for Audit Trial kept by application manager
//
// swagger:model
type AuditRecord struct {
	ID              uuid.UUID             `json:"id" gorm:"primaryKey"`
	CreatedAt       time.Time             `json:"createdat" gorm:"autoCreateTime;index;not null"`
	RequestID       uuid.UUID             `json:"request_id" gorm:"index;not null"`
	ExecutionID     uuid.UUID             `json:"executionid"`
	VersionID       uuid.UUID             `json:"versionid" gorm:"index"`
	ApplicationID   uuid.UUID             `json:"applicationid" gorm:"index"`
	VersionNumber   int                   `json:"version_number" gorm:"index"`
	ExecutionStatus CommandStatusTypeEnum `json:"execution_status" gorm:"index"`
	StartTime       time.Time             `json:"start_time"`
	EndTime         time.Time             `json:"end_time"`
	Command         string                `json:"command"`
	FullCommand     string                `json:"full_command"`
	Output          string                `json:"output"`
	Error           string                `json:"error"`
	ErrorCode       string                `json:"error_code"`
	Done            chan bool             `json:"-" gorm:"-"`
	Action          ActionTypeEnum        `json:"action" gorm:"not null;index"`
	UserID          uuid.UUID             `json:"userid" validate:"required" gorm:"index;not null"`
	Status          ActionStatusTypeEnum  `json:"status" validate:"required" gorm:"index;not null"`
	Details         string                `json:"details" validate:"required"`
}

// CommandOutputWrapper represents schema for response of command executed by application manager including output
//
// swagger:model
type AuditRecordWrapper struct {
	ID              uuid.UUID             `json:"id" gorm:"primaryKey"`
	CreatedAt       time.Time             `json:"createdat" gorm:"autoCreateTime;index;not null"`
	RequestID       uuid.UUID             `json:"request_id" gorm:"index;not null"`
	ExecutionID     uuid.UUID             `json:"executionid"`
	VersionID       uuid.UUID             `json:"versionid" gorm:"index"`
	ApplicationID   uuid.UUID             `json:"applicationid" gorm:"index"`
	VersionNumber   int                   `json:"version_number" gorm:"index"`
	ExecutionStatus CommandStatusTypeEnum `json:"execution_status" gorm:"index"`
	StartTime       time.Time             `json:"start_time"`
	EndTime         time.Time             `json:"end_time"`
	Command         string                `json:"command"`
	Output          string                `json:"output"`
	Error           string                `json:"error"`
	ErrorCode       string                `json:"error_code"`
	Action          ActionTypeEnum        `json:"action" gorm:"not null;index"`
	UserID          uuid.UUID             `json:"userid" validate:"required" gorm:"index;not null"`
	Status          ActionStatusTypeEnum  `json:"status" validate:"required" gorm:"index;not null"`
	Details         string                `json:"details" validate:"required"`
}
