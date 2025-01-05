package handlers

import (
	"DemoServer_ApplicationManager/data"
	"net/http"
)

func (h *ApplicationHandler) Validate(w http.ResponseWriter, r *http.Request) {
	command := "terragrunt validate"
	h.VersionExecIacCommand(w, r, command, data.Validate)
}

func (h *ApplicationHandler) Plan(w http.ResponseWriter, r *http.Request) {
	command := "terragrunt plan"
	h.VersionExecIacCommand(w, r, command, data.Plan)
}

func (h *ApplicationHandler) Apply(w http.ResponseWriter, r *http.Request) {
	command := "terragrunt apply --auto-approve"
	h.VersionExecIacCommand(w, r, command, data.Apply)
}

func (h *ApplicationHandler) Destroy(w http.ResponseWriter, r *http.Request) {
	command := "terragrunt destroy --auto-approve"
	h.VersionExecIacCommand(w, r, command, data.Destroy)
}

func (h *ApplicationHandler) TGVersion(w http.ResponseWriter, r *http.Request) {
	command := "terragrunt version"
	h.VersionExecIacCommand(w, r, command, data.TGVersion)
}

func (h *ApplicationHandler) RunAll(w http.ResponseWriter, r *http.Request) {
	command := "terragrunt run-all"
	h.VersionExecIacCommand(w, r, command, data.RunAll)
}

func (h *ApplicationHandler) RenderJson(w http.ResponseWriter, r *http.Request) {
	command := "terragrunt render-json"
	h.VersionExecIacCommand(w, r, command, data.RenderJson)
}

func (h *ApplicationHandler) Test(w http.ResponseWriter, r *http.Request) {
	command := "terragrunt test"
	h.VersionExecIacCommand(w, r, command, data.Test)
}

func (h *ApplicationHandler) Untaint(w http.ResponseWriter, r *http.Request) {
	command := "terragrunt untaint"
	h.VersionExecIacCommand(w, r, command, data.Untaint)
}

func (h *ApplicationHandler) Taint(w http.ResponseWriter, r *http.Request) {
	command := "terragrunt taint"
	h.VersionExecIacCommand(w, r, command, data.Taint)
}

func (h *ApplicationHandler) ValidateInputs(w http.ResponseWriter, r *http.Request) {
	command := "terragrunt validate-inputs"
	h.VersionExecIacCommand(w, r, command, data.ValidateInputs)
}

func (h *ApplicationHandler) Providers(w http.ResponseWriter, r *http.Request) {
	command := "terragrunt providers"
	h.VersionExecIacCommand(w, r, command, data.Providers)
}

func (h *ApplicationHandler) ForceUnlock(w http.ResponseWriter, r *http.Request) {
	command := "terragrunt force-unlock"
	h.VersionExecIacCommand(w, r, command, data.ForceUnlock)
}

func (h *ApplicationHandler) HclFmt(w http.ResponseWriter, r *http.Request) {
	command := "terragrunt hclfmt"
	h.VersionExecIacCommand(w, r, command, data.HclFmt)
}

func (h *ApplicationHandler) Fmt(w http.ResponseWriter, r *http.Request) {
	command := "terragrunt fmt"
	h.VersionExecIacCommand(w, r, command, data.Fmt)
}

func (h *ApplicationHandler) GetIacCommandResult(w http.ResponseWriter, r *http.Request) {

	h.VersionIacCommandResult(w, r, r.Context())
}

func (h *ApplicationHandler) Init(w http.ResponseWriter, r *http.Request) {

	command := "terragrunt init"
	h.VersionExecIacCommand(w, r, command, data.Init)
}

func (h *ApplicationHandler) HclValidate(w http.ResponseWriter, r *http.Request) {
	command := "terragrunt hclvalidate"
	h.VersionExecIacCommand(w, r, command, data.HclValidate)
}

func (h *ApplicationHandler) Output(w http.ResponseWriter, r *http.Request) {
	command := "terragrunt output"
	h.VersionExecIacCommand(w, r, command, data.Output)
}

func (h *ApplicationHandler) Refresh(w http.ResponseWriter, r *http.Request) {
	command := "terragrunt refresh"
	h.VersionExecIacCommand(w, r, command, data.Refresh)
}

func (h *ApplicationHandler) CreateWorkspace(w http.ResponseWriter, r *http.Request) {
	command := "terragrunt workspace create"
	h.VersionExecIacCommand(w, r, command, data.CreateWorkspace)
}

func (h *ApplicationHandler) DeleteWorkspace(w http.ResponseWriter, r *http.Request) {
	command := "terragrunt workspace delete"
	h.VersionExecIacCommand(w, r, command, data.DeleteWorkspace)
}

func (h *ApplicationHandler) ShowWorkspace(w http.ResponseWriter, r *http.Request) {
	command := "terragrunt workspace show"
	h.VersionExecIacCommand(w, r, command, data.ShowWorkspace)
}

func (h *ApplicationHandler) SelectWorkspace(w http.ResponseWriter, r *http.Request) {
	command := "terragrunt workspace select"
	h.VersionExecIacCommand(w, r, command, data.SelectWorkspace)
}

func (h *ApplicationHandler) GetWorkspaces(w http.ResponseWriter, r *http.Request) {
	command := "terragrunt workspaces"
	h.VersionExecIacCommand(w, r, command, data.ListWorkspace)
}

func (h *ApplicationHandler) ImportStateResource(w http.ResponseWriter, r *http.Request) {
	command := "terragrunt state resource import"
	h.VersionExecIacCommand(w, r, command, data.ImportStateResource)
}

func (h *ApplicationHandler) RemoveStateResource(w http.ResponseWriter, r *http.Request) {
	command := "terragrunt state resource remove"
	h.VersionExecIacCommand(w, r, command, data.RemoveStateResource)
}

func (h *ApplicationHandler) MoveStateResource(w http.ResponseWriter, r *http.Request) {
	command := "terragrunt state resource move"
	h.VersionExecIacCommand(w, r, command, data.MoveStateResource)
}

func (h *ApplicationHandler) ListState(w http.ResponseWriter, r *http.Request) {
	command := "terragrunt state list"
	h.VersionExecIacCommand(w, r, command, data.ListState)
}
