package data

import (
	"DemoServer_ApplicationManager/helper"
	"bytes"
	"encoding/json"
	"strings"
)

type VersionStateTypeEnum int

const (
	NoVersionState VersionStateTypeEnum = iota
	Draft
	Published
	Archived
)

func (o VersionStateTypeEnum) String() string {
	return versionstate_toString[o]
}

var versionstate_toString = map[VersionStateTypeEnum]string{
	NoVersionState: strings.ToLower(""),
	Draft:          strings.ToLower("Draft"),
	Published:      strings.ToLower("Published"),
	Archived:       strings.ToLower("Archived"),
}

var versionstate_toID = map[string]VersionStateTypeEnum{
	strings.ToLower(""):          NoVersionState,
	strings.ToLower("Draft"):     Draft,
	strings.ToLower("Published"): Published,
	strings.ToLower("Archived"):  Archived,
}

// MarshalJSON marshals the enum as a quoted json string
func (o VersionStateTypeEnum) MarshalJSON() ([]byte, error) {
	buffer := bytes.NewBufferString(`"`)
	buffer.WriteString(strings.ToLower(versionstate_toString[o]))
	buffer.WriteString(`"`)
	return buffer.Bytes(), nil
}

// UnmarshalJSON unmashals a quoted json string to the enum value
func (o *VersionStateTypeEnum) UnmarshalJSON(b []byte) error {
	var j string
	err := json.Unmarshal(b, &j)
	if err != nil {
		return err
	}
	// Note that if the string cannot be found then it will be set to the zero value, 'Created' in this case.
	_, found := versionstate_toID[strings.ToLower(j)]

	if !found {
		return helper.ErrNotFound
	}

	*o = versionstate_toID[strings.ToLower(j)]

	return nil
}
