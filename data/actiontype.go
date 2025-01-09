package data

import (
	"DemoServer_ApplicationManager/helper"
	"bytes"
	"database/sql/driver"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/google/uuid"
)

type ActionTypeEnum uuid.UUID

var (
	NoAction            = ActionTypeEnum(uuid.MustParse("bed520e1-da96-4491-ac04-56230f3adc0f"))
	CreateApp           = ActionTypeEnum(uuid.MustParse("2e95198d-279b-425e-91a5-2453886e9afb"))
	UpdateApp           = ActionTypeEnum(uuid.MustParse("eae87971-6e01-47d7-bd75-5341f4d4067f"))
	DeleteApp           = ActionTypeEnum(uuid.MustParse("43f67a04-adcd-4ad3-b581-9563133c5acc"))
	CreateVersion       = ActionTypeEnum(uuid.MustParse("923848c1-4dd3-4933-9836-24692d2febe0"))
	PatchVersion        = ActionTypeEnum(uuid.MustParse("88ebe210-312f-4db7-9414-c21a23bf63df"))
	SetVersionState     = ActionTypeEnum(uuid.MustParse("6f37e9e3-b71b-48d1-a75e-5bc1631b2e77"))
	ArchiveVersion      = ActionTypeEnum(uuid.MustParse("674eb6bc-53d0-4562-8662-011c40a3d873"))
	UploadPackage       = ActionTypeEnum(uuid.MustParse("606f4fde-5c2a-4cb4-92ba-e73b3438f8e2"))
	DownloadPackage     = ActionTypeEnum(uuid.MustParse("63fdafcc-b4c1-499e-80ea-26014866f6ff"))
	ListState           = ActionTypeEnum(uuid.MustParse("103c8677-2c27-456f-8807-391aba60dd3a"))
	MoveStateResource   = ActionTypeEnum(uuid.MustParse("2849966e-41b1-4800-ad69-73472b185bb0"))
	RemoveStateResource = ActionTypeEnum(uuid.MustParse("f846760b-10bf-4420-a7f8-b76af790e2a3"))
	ImportStateResource = ActionTypeEnum(uuid.MustParse("16a7f4f0-ab61-4b4c-a5c8-61aedd6a3ae9"))
	CreateWorkspace     = ActionTypeEnum(uuid.MustParse("326a17fa-fbe9-4b51-8686-62a7918ff824"))
	ListWorkspace       = ActionTypeEnum(uuid.MustParse("351e7094-7bc9-4c49-a50a-9453156656ef"))
	SelectWorkspace     = ActionTypeEnum(uuid.MustParse("da6d54e5-c37f-43f1-b84e-2144b86a83b2"))
	ShowWorkspace       = ActionTypeEnum(uuid.MustParse("5a5e8bc6-fd67-4d4b-83eb-05ff38b17216"))
	DeleteWorkspace     = ActionTypeEnum(uuid.MustParse("0404ae5d-01e5-43f3-a143-10e4d8a9dbbd"))
	GraphTofu           = ActionTypeEnum(uuid.MustParse("97765022-9502-4531-bcb9-a8e8ea16860c"))
	Output              = ActionTypeEnum(uuid.MustParse("742b0fdf-0bf9-4663-b2c9-0126c2e4f0f5"))
	Refresh             = ActionTypeEnum(uuid.MustParse("a129197a-22ec-489e-9612-6b5443ce9056"))
	GetTofuVersion      = ActionTypeEnum(uuid.MustParse("3429f62f-f5a3-4836-b5c9-09295a504c4d"))
	GetTGVersion        = ActionTypeEnum(uuid.MustParse("fb0651f8-3f2f-4509-adc0-f8dedb4096f3"))
	Destroy             = ActionTypeEnum(uuid.MustParse("6cc25733-5bd2-4fe2-97b8-b42fb7732ec8"))
	Apply               = ActionTypeEnum(uuid.MustParse("6745fd96-5874-416f-b515-cd708cff9076"))
	Plan                = ActionTypeEnum(uuid.MustParse("65408328-09e0-48ca-9261-2fc56d5dfb0c"))
	Validate            = ActionTypeEnum(uuid.MustParse("d7ea7e14-4c68-4f04-bb31-8486d61b228e"))
	HclValidate         = ActionTypeEnum(uuid.MustParse("0cc51f49-3b6d-46de-aa6a-e5615f4dbf1a"))
	Init                = ActionTypeEnum(uuid.MustParse("973177fb-9283-495e-8176-044404b7232a"))
	Fmt                 = ActionTypeEnum(uuid.MustParse("75a550ff-c552-48ad-b720-458a742fb5ac"))
	HclFmt              = ActionTypeEnum(uuid.MustParse("ec18cab2-140d-4eeb-89ae-0ccc60a770e5"))
	ForceUnlock         = ActionTypeEnum(uuid.MustParse("e7f85f55-e14f-46ad-917e-5f3a44556d50"))
	Providers           = ActionTypeEnum(uuid.MustParse("b45441fa-d1fb-49bc-8006-89f76a0ed331"))
	Taint               = ActionTypeEnum(uuid.MustParse("4b3e4cc7-0f6d-4cad-a5be-ebe57a6b24db"))
	Untaint             = ActionTypeEnum(uuid.MustParse("1a1de737-b2e8-47ca-a40d-b4a675256614"))
	Test                = ActionTypeEnum(uuid.MustParse("7b64965a-7b52-4545-8c60-9104b30c512b"))
	Render              = ActionTypeEnum(uuid.MustParse("d59b18b2-72df-433d-a255-08d88a25b5a7"))
	RunAll              = ActionTypeEnum(uuid.MustParse("ad717ae9-26c6-49f5-b246-c3d8b6ac3eb4"))
	ValidateInputs      = ActionTypeEnum(uuid.MustParse("63da81a6-0e3c-40d6-933f-3f936749a2a6"))
	LSPackage           = ActionTypeEnum(uuid.MustParse("0c85ea42-7bcf-49cd-8f47-9732180c5f26"))
)

func (o ActionTypeEnum) String() string {
	return action_toString[o]
}

var action_toString = map[ActionTypeEnum]string{
	NoAction:            strings.ToLower(""),
	CreateApp:           strings.ToLower(""),
	UpdateApp:           strings.ToLower(""),
	DeleteApp:           strings.ToLower(""),
	CreateVersion:       strings.ToLower(""),
	PatchVersion:        strings.ToLower(""),
	SetVersionState:     strings.ToLower(""),
	ArchiveVersion:      strings.ToLower(""),
	UploadPackage:       strings.ToLower(""),
	DownloadPackage:     strings.ToLower(""),
	ListState:           strings.ToLower(""),
	MoveStateResource:   strings.ToLower(""),
	RemoveStateResource: strings.ToLower(""),
	ImportStateResource: strings.ToLower(""),
	ListWorkspace:       strings.ToLower(""),
	SelectWorkspace:     strings.ToLower(""),
	ShowWorkspace:       strings.ToLower(""),
	DeleteWorkspace:     strings.ToLower(""),
	GraphTofu:           strings.ToLower(""),
	Output:              strings.ToLower(""),
	Refresh:             strings.ToLower(""),
	GetTofuVersion:      strings.ToLower(""),
	GetTGVersion:        strings.ToLower(""),
	Destroy:             strings.ToLower(""),
	Apply:               strings.ToLower(""),
	Plan:                strings.ToLower(""),
	Validate:            strings.ToLower(""),
	HclValidate:         strings.ToLower(""),
	Init:                strings.ToLower(""),
	Fmt:                 strings.ToLower(""),
	HclFmt:              strings.ToLower(""),
	ForceUnlock:         strings.ToLower(""),
	Providers:           strings.ToLower(""),
	Taint:               strings.ToLower(""),
	Untaint:             strings.ToLower(""),
	Test:                strings.ToLower(""),
	Render:              strings.ToLower(""),
	RunAll:              strings.ToLower(""),
}

var action_toID = map[string]ActionTypeEnum{
	strings.ToLower(""): NoAction,
	strings.ToLower(""): CreateApp,
	strings.ToLower(""): UpdateApp,
	strings.ToLower(""): DeleteApp,
	strings.ToLower(""): CreateVersion,
	strings.ToLower(""): PatchVersion,
	strings.ToLower(""): SetVersionState,
	strings.ToLower(""): ArchiveVersion,
	strings.ToLower(""): UploadPackage,
	strings.ToLower(""): DownloadPackage,
	strings.ToLower(""): ListState,
	strings.ToLower(""): MoveStateResource,
	strings.ToLower(""): RemoveStateResource,
	strings.ToLower(""): ImportStateResource,
	strings.ToLower(""): ListWorkspace,
	strings.ToLower(""): SelectWorkspace,
	strings.ToLower(""): ShowWorkspace,
	strings.ToLower(""): DeleteWorkspace,
	strings.ToLower(""): GraphTofu,
	strings.ToLower(""): Output,
	strings.ToLower(""): Refresh,
	strings.ToLower(""): GetTofuVersion,
	strings.ToLower(""): GetTGVersion,
	strings.ToLower(""): Destroy,
	strings.ToLower(""): Apply,
	strings.ToLower(""): Plan,
	strings.ToLower(""): Validate,
	strings.ToLower(""): HclValidate,
	strings.ToLower(""): Init,
	strings.ToLower(""): Fmt,
	strings.ToLower(""): HclFmt,
	strings.ToLower(""): ForceUnlock,
	strings.ToLower(""): Providers,
	strings.ToLower(""): Taint,
	strings.ToLower(""): Untaint,
	strings.ToLower(""): Test,
	strings.ToLower(""): Render,
	strings.ToLower(""): RunAll,
}

// MarshalJSON marshals the enum as a quoted json string
func (o ActionTypeEnum) MarshalJSON() ([]byte, error) {
	buffer := bytes.NewBufferString(`"`)
	buffer.WriteString(strings.ToLower(action_toString[o]))
	buffer.WriteString(`"`)
	return buffer.Bytes(), nil
}

// UnmarshalJSON unmashals a quoted json string to the enum value
func (o *ActionTypeEnum) UnmarshalJSON(b []byte) error {
	var j string
	err := json.Unmarshal(b, &j)
	if err != nil {
		return err
	}
	// Note that if the string cannot be found then it will be set to the zero value, 'Created' in this case.
	_, found := action_toID[strings.ToLower(j)]

	if !found {
		return helper.ErrNotFound
	}

	*o = ActionTypeEnum(action_toID[strings.ToLower(j)])

	return nil
}

// Scan implements the Scanner interface for ActionTypeEnum
func (a *ActionTypeEnum) Scan(value interface{}) error {
	bytes, ok := value.([]byte)
	if !ok {
		return fmt.Errorf("failed to scan ActionTypeEnum: %v", value)
	}

	parsedUUID, err := uuid.FromBytes(bytes)
	if err != nil {
		return fmt.Errorf("failed to parse UUID: %w", err)
	}

	*a = ActionTypeEnum(parsedUUID)
	return nil
}

// Value implements the Valuer interface for ActionTypeEnum
func (a ActionTypeEnum) Value() (driver.Value, error) {
	uuidValue := uuid.UUID(a) // Convert ActionTypeEnum to uuid.UUID
	return uuidValue.MarshalBinary()
}
