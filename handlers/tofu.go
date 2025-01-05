package handlers

import (
	"DemoServer_ApplicationManager/data"
	"net/http"
)

func (h *ApplicationHandler) TofuVersion(w http.ResponseWriter, r *http.Request) {
	command := "tofu version"
	h.VersionExecIacCommand(w, r, command, data.VersionTofu)
}

func (h *ApplicationHandler) GraphTofu(w http.ResponseWriter, r *http.Request) {
	command := "terragrunt validate"
	h.VersionExecIacCommand(w, r, command, data.GraphTofu)
}
