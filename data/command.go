package data

import (
	"time"

	"github.com/google/uuid"
)

// CommandOutputWrapper represents schema for response of command executed by application manager including output
//
// swagger:model
type CommandOutput struct {
	ExecutionID   uuid.UUID `json:"executionid"`
	VersionID     uuid.UUID `json:"versionid"`
	ApplicationID string    `json:"applicationid"`
	VersionNumber int       `json:"version_number" gorm:"index"`
	StartTime     time.Time `json:"start_time"`
	EndTime       time.Time `json:"end_time"`
	Command       string    `json:"command"`
	FullCommand   string    `json:"full_command"`
	Output        string    `json:"output"`
	Error         string    `json:"error"`
	ErrorCode     string    `json:"error_code"`
	Done          chan bool `json:"_"`
}

// CommandOutputWrapper represents schema for response of command executed by application manager including output
//
// swagger:model
type CommandOutputWrapper struct {
	ExecutionID   uuid.UUID `json:"executionid"`
	VersionID     uuid.UUID `json:"versionid"`
	ApplicationID string    `json:"applicationid"`
	VersionNumber int       `json:"version_number" gorm:"index"`
	StartTime     time.Time `json:"start_time"`
	EndTime       time.Time `json:"end_time"`
	Command       string    `json:"command"`
	Output        string    `json:"output"`
	Error         string    `json:"error"`
}
