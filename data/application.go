package data

import (
	"DemoServer_ApplicationManager/configuration"
	"encoding/json"
	"io"
	"time"

	"github.com/go-playground/validator"
	"github.com/google/uuid"
)

// Application represents generic Application resource returned by Microservice endpoints
//
// swagger:model
type Application struct {
	ID        uuid.UUID `json:"id" gorm:"primaryKey"`
	CreatedAt time.Time `json:"createdat" gorm:"autoCreateTime;index;not null"`
	UpdatedAt time.Time `json:"updatedat" gorm:"autoUpdateTime;index"`

	OwnerID string `json:"ownerid" validate:"required,uuid4" gorm:"index;not null"`

	// User friendly name for Application
	// required: true
	Name string `json:"name" validate:"required" gorm:"index;not null;unique"`

	// Description of Application
	// required: false
	Description string `json:"description" gorm:"index"`

	// State of Application
	// required: true
	State ApplicationStateTypeEnum `json:"state" validate:"required" gorm:"index"`

	// Cloud Connection to be used for orchestration of application
	// required: false
	ConnectionID string `json:"connectionid,omitempty" validate:"omitempty,uuid4" gorm:"index"`

	Versions []Version `json:"versions"`
}

// ApplicationsResponse represents generic Application attributes which are returned in response of GET on applications endpoint.
//
// swagger:model
type ApplicationsResponse struct {
	// Number of skipped resources
	// required: true
	Skip int `json:"skip"`

	// Limit applied on resources returned
	// required: true
	Limit int `json:"limit"`

	// Total number of resources returned
	// required: true
	Total int `json:"total"`

	// Connection resource objects
	// required: true
	Applications []ApplicationResponseWrapper `json:"applications"`
}

// AWSConnectionPostWrapper represents AWSConnection attributes for POST request body schema.
// swagger:model
type ApplicationPostWrapper struct {
	// User friendly name for Application
	// required: true
	Name string `json:"name" validate:"required" gorm:"index;not null;unique"`

	// Description of Application
	// required: false
	Description string `json:"description" gorm:"index"`

	// State of Application
	// required: true
	State ApplicationStateTypeEnum `json:"state" validate:"required" gorm:"index"`

	// Cloud Connection to be used for orchestration of application
	// required: false
	ConnectionID string `json:"connectionid,omitempty" validate:"omitempty,uuid4" gorm:"index"`
}

// ApplicationPatchWrapper represents Application attributes for PATCH request body schema.
// swagger:model
type ApplicationPatchWrapper struct {
	// Description of Application
	// required: false
	Description *string `json:"description,omitempty" validate:"omitempty"`

	// State of Application
	// required: true
	State *ApplicationStateTypeEnum `json:"state,omitempty" validate:"omitempty"`

	// Cloud Connection to be used for orchestration of application
	// required: false
	ConnectionID *string `json:"connectionid,omitempty" validate:"omitempty,uuid"`
}

// ApplicationResponseWrapper represents information Application resource returned by Post, Get and List endpoints
// swagger:model
type ApplicationResponseWrapper struct {
	ID        uuid.UUID `json:"id" gorm:"primaryKey"`
	CreatedAt time.Time `json:"createdat" gorm:"autoCreateTime;index;not null"`
	UpdatedAt time.Time `json:"updatedat" gorm:"autoUpdateTime;index"`

	OwnerID string `json:"ownerid" validate:"required,uuid4" gorm:"index;not null"`

	// User friendly name for Application
	// required: true
	Name string `json:"name" validate:"required" gorm:"index;not null;unique"`

	// Description of Application
	// required: false
	Description string `json:"description" gorm:"index"`

	// State of Application
	// required: true
	State ApplicationStateTypeEnum `json:"state" gorm:"index"`

	ConnectionID string `json:"connectionid" validate:"uuid4" gorm:"index"`
}

// DeleteApplicationResponse represents Response schema for DELETE - Application
// swagger:model
type DeleteApplicationResponse struct {
	// Descriptive human readable HTTP status of delete operation.
	// in: status
	Status string `json:"status"`

	// HTTP status code for delete operation.
	// in: statusCode
	StatusCode int `json:"statusCode"`
}

type Applications []*Application

func NewApplication(cfg *configuration.Config) *Application {
	var a Application

	a.ID = uuid.New()
	a.State = ApplicationState_Activated

	return &a
}

func InitApplication(id string, cfg *configuration.Config) *Application {
	var a Application

	a.ID, _ = uuid.Parse(id)

	return &a
}

func (a *Application) GetNewID() {
	a.ID = uuid.New()
}

func (a *Application) FromJSON(r io.Reader) error {
	e := json.NewDecoder(r)
	err := e.Decode(a)

	return err
}

func (a *Application) Validate() error {
	validate := validator.New()
	return validate.Struct(a)
}

func (a *Application) ToJSON(w io.Writer) error {
	e := json.NewEncoder(w)
	return e.Encode(a)
}

func (a *Application) Initialize() {

}

func (a *Application) NewVersion() *Version {

	v := NewVersion(len(a.Versions)+1, a.ID)

	a.Versions = append(a.Versions, *v)

	return v
}
