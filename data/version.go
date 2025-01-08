package data

import (
	"time"

	"github.com/google/uuid"
)

// Version represents different version of application resources
//
// swagger:model
type Version struct {
	ID        uuid.UUID `json:"id" gorm:"primaryKey"`
	CreatedAt time.Time `json:"createdat" gorm:"autoCreateTime;index;not null"`
	UpdatedAt time.Time `json:"updatedat" gorm:"autoUpdateTime;index"`

	// Description of Version
	// required: false
	VersionNumber int `json:"version_number" gorm:"index"`

	// Description of Version
	// required: false
	Description string `json:"description" gorm:"index"`

	ApplicationID uuid.UUID `json:"applicationid" gorm:"not null;index;constraint:OnUpdate:CASCADE,OnDelete:CASCADE"`

	State VersionStateTypeEnum `json:"state" gorm:"index;not null"`

	PackageUploaded   bool      `json:"package_uploaded"`
	PackageUploadedAt time.Time `json:"package_uploaded_at"`
	PackagePath       string    `json:"package_path"`

	DemoStatus          VersionDemoStatusTypeEnum `json:"demo_status" gorm:"demo_status"`
	DemoStartTime       time.Time                 `json:"demo_start_time"`
	DemoActualEndTime   time.Time                 `json:"demo_actual_end_time"`
	DemoExpectedEndTime time.Time                 `json:"demo_expected_end_time"`
	DemoDuration        int                       `json:"demo_duration"`

	LockOwner string `json:"lock_owner" gorm:"index"`

	UsageCounter  int       `json:"usage_counter"`
	LatestApply   time.Time `json:"latest_apply"`
	LatestDestroy time.Time `json:"latest_destroy"`
	LatestInit    time.Time `json:"latest_init"`
}

// VersionResponseWrapper represents schema of response to GET - Version endpoint
//
// swagger:model
type VersionResponseWrapper struct {
	ID        uuid.UUID `json:"id" gorm:"primaryKey"`
	CreatedAt time.Time `json:"createdat" gorm:"autoCreateTime;index;not null"`
	UpdatedAt time.Time `json:"updatedat" gorm:"autoUpdateTime;index"`

	// Description of Version
	// required: false
	VersionNumber int `json:"version_number" gorm:"index"`

	// Description of Version
	// required: false
	Description string `json:"description" gorm:"index"`

	ApplicationID uuid.UUID `json:"applicationid" gorm:"not null;index;constraint:OnUpdate:CASCADE,OnDelete:CASCADE"`

	State VersionStateTypeEnum `json:"state" gorm:"index;not null"`

	PackageUploaded   bool      `json:"package_uploaded"`
	PackageUploadedAt time.Time `json:"package_uploaded_at"`

	DemoStatus          VersionDemoStatusTypeEnum `json:"demo_status" gorm:"-"`
	DemoStartTime       time.Time                 `json:"demo_start_time"`
	DemoExpectedEndTime time.Time                 `json:"demo_expected_end_time"`
	DemoActualEndTime   time.Time                 `json:"demo_actual_end_time"`
	DemoDuration        int                       `json:"demo_duration"`

	UsageCounter  int       `json:"usage_counter"`
	LatestApply   time.Time `json:"latest_apply"`
	LatestDestroy time.Time `json:"latest_destroy"`
}

// VersionsResponse represents generic Version attributes which are returned in response of GET on versions endpoint.
//
// swagger:model
type VersionsResponse struct {
	// Number of skipped resources
	// required: true
	Skip int `json:"skip"`

	// Limit applied on resources returned
	// required: true
	Limit int `json:"limit"`

	// Total number of resources returned
	// required: true
	Total int `json:"total"`

	// Version resource objects
	// required: true
	Versions []VersionResponseWrapper `json:"versions"`
}

func NewVersion(versionNumber int, applicationID uuid.UUID) *Version {
	var v Version

	v.ID = uuid.New()
	v.VersionNumber = versionNumber
	v.State = Draft
	v.PackageUploaded = false

	return &v
}
