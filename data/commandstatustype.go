package data

import (
	"DemoServer_ApplicationManager/helper"
	"bytes"
	"encoding/json"
	"strings"
)

type CommandStatusTypeEnum int

const (
	NoCommandStatus CommandStatusTypeEnum = iota
	InProcess
	Completed
)

func (o CommandStatusTypeEnum) String() string {
	return commandstatus_toString[o]
}

var commandstatus_toString = map[CommandStatusTypeEnum]string{
	NoCommandStatus: strings.ToLower(""),
	InProcess:       strings.ToLower("InProcess"),
	Completed:       strings.ToLower("Completed"),
}

var commandstatus_toID = map[string]CommandStatusTypeEnum{
	strings.ToLower(""):          NoCommandStatus,
	strings.ToLower("InProcess"): InProcess,
	strings.ToLower("Completed"): Completed,
}

// MarshalJSON marshals the enum as a quoted json string
func (o CommandStatusTypeEnum) MarshalJSON() ([]byte, error) {
	buffer := bytes.NewBufferString(`"`)
	buffer.WriteString(strings.ToLower(commandstatus_toString[o]))
	buffer.WriteString(`"`)
	return buffer.Bytes(), nil
}

// UnmarshalJSON unmashals a quoted json string to the enum value
func (o *CommandStatusTypeEnum) UnmarshalJSON(b []byte) error {
	var j string
	err := json.Unmarshal(b, &j)
	if err != nil {
		return err
	}
	// Note that if the string cannot be found then it will be set to the zero value, 'Created' in this case.
	_, found := commandstatus_toID[strings.ToLower(j)]

	if !found {
		return helper.ErrNotFound
	}

	*o = commandstatus_toID[strings.ToLower(j)]

	return nil
}
