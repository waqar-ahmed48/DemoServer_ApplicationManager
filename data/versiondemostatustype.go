package data

import (
	"DemoServer_ApplicationManager/helper"
	"bytes"
	"encoding/json"
	"strings"
)

type VersionDemoStatusTypeEnum int

const (
	NoDemoStatus VersionDemoStatusTypeEnum = iota
	Demo_Running
	Demo_Stopped
	Demo_Starting
	Demo_Stopping
	Demo_FailedToStart
	Demo_FailedToStop
)

func (o VersionDemoStatusTypeEnum) String() string {
	return versiondemostatus_toString[o]
}

var versiondemostatus_toString = map[VersionDemoStatusTypeEnum]string{
	NoDemoStatus:       strings.ToLower(""),
	Demo_Running:       strings.ToLower("Running"),
	Demo_Stopped:       strings.ToLower("Stopped"),
	Demo_Starting:      strings.ToLower("Starting"),
	Demo_Stopping:      strings.ToLower("Stopping"),
	Demo_FailedToStart: strings.ToLower("Failed To Start"),
	Demo_FailedToStop:  strings.ToLower("Failed To Stop"),
}

var versiondemostatus_toID = map[string]VersionDemoStatusTypeEnum{
	strings.ToLower(""):                NoDemoStatus,
	strings.ToLower("Running"):         Demo_Running,
	strings.ToLower("Stopped"):         Demo_Stopped,
	strings.ToLower("Starting"):        Demo_Starting,
	strings.ToLower("Stopping"):        Demo_Stopping,
	strings.ToLower("Failed To Start"): Demo_FailedToStart,
	strings.ToLower("Failed To Stop"):  Demo_FailedToStop,
}

// MarshalJSON marshals the enum as a quoted json string
func (o VersionDemoStatusTypeEnum) MarshalJSON() ([]byte, error) {
	buffer := bytes.NewBufferString(`"`)
	buffer.WriteString(strings.ToLower(versiondemostatus_toString[o]))
	buffer.WriteString(`"`)
	return buffer.Bytes(), nil
}

// UnmarshalJSON unmashals a quoted json string to the enum value
func (o *VersionDemoStatusTypeEnum) UnmarshalJSON(b []byte) error {
	var j string
	err := json.Unmarshal(b, &j)
	if err != nil {
		return err
	}
	// Note that if the string cannot be found then it will be set to the zero value, 'Created' in this case.
	_, found := versiondemostatus_toID[strings.ToLower(j)]

	if !found {
		return helper.ErrNotFound
	}

	*o = versiondemostatus_toID[strings.ToLower(j)]

	return nil
}
