package data

import (
	"DemoServer_ApplicationManager/helper"
	"bytes"
	"encoding/json"
	"strings"
)

type ApplicationStateTypeEnum int

const (
	NoApplicationState ApplicationStateTypeEnum = iota
	ApplicationState_Activated
	ApplicationState_Deactivated
)

func (o ApplicationStateTypeEnum) String() string {
	return applicationstate_toString[o]
}

var applicationstate_toString = map[ApplicationStateTypeEnum]string{
	NoApplicationState:           strings.ToLower(""),
	ApplicationState_Activated:   strings.ToLower("Activated"),
	ApplicationState_Deactivated: strings.ToLower("Deactivated"),
}

var applicationstate_toID = map[string]ApplicationStateTypeEnum{
	strings.ToLower(""):            NoApplicationState,
	strings.ToLower("Activated"):   ApplicationState_Activated,
	strings.ToLower("Deactivated"): ApplicationState_Deactivated,
}

// MarshalJSON marshals the enum as a quoted json string
func (o ApplicationStateTypeEnum) MarshalJSON() ([]byte, error) {
	buffer := bytes.NewBufferString(`"`)
	buffer.WriteString(strings.ToLower(applicationstate_toString[o]))
	buffer.WriteString(`"`)
	return buffer.Bytes(), nil
}

// UnmarshalJSON unmashals a quoted json string to the enum value
func (o *ApplicationStateTypeEnum) UnmarshalJSON(b []byte) error {
	var j string
	err := json.Unmarshal(b, &j)
	if err != nil {
		return err
	}
	// Note that if the string cannot be found then it will be set to the zero value, 'Created' in this case.
	_, found := applicationstate_toID[strings.ToLower(j)]

	if !found {
		return helper.ErrNotFound
	}

	*o = applicationstate_toID[strings.ToLower(j)]

	return nil
}
