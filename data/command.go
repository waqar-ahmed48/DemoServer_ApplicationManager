package data

import "github.com/google/uuid"

// CommandOutputWrapper represents schema for response of command executed by application manager including output
//
// swagger:model
type CommandOutputWrapper struct {
	VersionID     uuid.UUID `json:"versionid"`
	ApplicationID string    `json:"applicationid"`
	VersionNumber int       `json:"version_number" gorm:"index"`
	Command       string    `json:"command"`
	Output        string    `json:"output"`
	Error         string    `json:"error"`
}
