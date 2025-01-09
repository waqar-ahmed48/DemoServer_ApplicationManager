package data

import (
	"time"

	"github.com/google/uuid"
)

type CredsAWSConnectionResponse struct {
	// connectionid for AWSConnection which was used to generate credentials
	// out: id
	ConnectionID string `json:"connectionid"`

	// LeaseID for generated access
	// out: lease_id
	LeaseID string `json:"lease_id"`

	// LeaseDuration for generated access
	// out: lease_duration
	LeaseDuration int `json:"lease_duration"`

	// Latency in seconds before credentials can be used with AWS
	// out: latency
	Latency int `json:"latency"`

	Data struct {
		// AccessKey for generated access
		// out: access_key
		AccessKey string `json:"access_key"`

		// SecretKey for generated access
		// out: secret_key
		SecretKey string `json:"secret_key"`

		// SessionToken for generated access
		// out: session_token
		SessionToken string `json:"session_token"`
	} `json:"data"`
}

type Connection struct {
	ID        uuid.UUID `json:"id" gorm:"primaryKey"`
	CreatedAt time.Time `json:"createdat" gorm:"autoCreateTime;index;not null"`
	UpdatedAt time.Time `json:"updatedat" gorm:"autoUpdateTime;index"`

	// User friendly name for Connection
	// required: true
	Name string `json:"name" validate:"required" gorm:"index;not null;unique"`

	// Description of Connection
	// required: false
	Description string `json:"description" gorm:"index"`

	// Type of connection.
	// required: true
	ConnectionType string `json:"connectiontype" gorm:"index;not null"`

	// Latest connectivity test result. 0 = Failed. 1 = Successful
	// required: false
	TestSuccessful int `json:"testsuccessful"`

	// Descriptive error for latest connectivity test
	// required: false
	TestError string `json:"testerror"`

	// Date and time of latest connectivity test whether it was successful or not
	// required: false
	TestedOn string `json:"testedon"`

	// Date and time of latest successful connectivity test
	// required: false
	LastSuccessfulTest string `json:"lastsuccessfultest"`

	// Applications consuming the connection
	// required: false
	Applications []string `json:"applications" gorm:"type:json"`
}

type AWSConnectionResponseWrapper struct {
	ID           uuid.UUID  `json:"id" gorm:"primaryKey"`
	CreatedAt    time.Time  `json:"createdat" gorm:"autoCreateTime;index;not null"`
	UpdatedAt    time.Time  `json:"updatedat" gorm:"autoUpdateTime;index"`
	ConnectionID uuid.UUID  `json:"connectionid" gorm:"not null;index"`
	Connection   Connection `json:"connection" gorm:"constraint:OnUpdate:CASCADE,OnDelete:CASCADE"`

	// AccessKey for AWS Account
	// required: true
	AccessKey string `json:"accesskey" validate:"required" gorm:"-"`

	// DefaultRegion for AWS Account
	// required: false
	DefaultRegion string `json:"default_region" gorm:"-"`

	// DefaultRegion for AWS Account
	// required: false
	DefaultLeaseTTL string `json:"default_lease_ttl" gorm:"-"`

	// DefaultRegion for AWS Account
	// required: false
	MaxLeaseTTL string `json:"max_lease_ttl" gorm:"-"`

	// RoleName RoleName for AWS Account
	// required: true
	RoleName string `json:"role_name" validate:"required" gorm:"-"`

	// CredentialType CredentialType for AWS Account Role
	// required: true
	CredentialType string `json:"credential_type" validate:"required,oneof=iam_user" gorm:"-"`

	// PolicyARNs PolicyARNs for AWS Account
	// required: true
	PolicyARNs []string `json:"policy_arns" validate:"required" gorm:"-"`
}
