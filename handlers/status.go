package handlers

import (
	"DemoServer_ApplicationManager/configuration"
	"DemoServer_ApplicationManager/datalayer"
	"DemoServer_ApplicationManager/helper"
	"DemoServer_ApplicationManager/utilities"
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/trace"
)

// Response schema for ApplicationManager Status GET
// swagger:model
type StatusResponse struct {
	// UP = UP, DOWN = DOWN
	// in: status
	Status string `json:"status"`
	// Down = ApplicationManager_Info_000003. UP = ApplicationManager_Info_000002
	// in: statusCode
	StatusCode string `json:"statusCode"`
	// date & time stamp for status check
	// in: timestamp
	Timestamp string `json:"timestamp"`
}

type StatusHandler struct {
	l   *slog.Logger
	pd  *datalayer.PostgresDataSource
	cfg *configuration.Config
}

func NewStatusHandler(l *slog.Logger, pd *datalayer.PostgresDataSource, cfg *configuration.Config) *StatusHandler {
	return &StatusHandler{l, pd, cfg}
}

// Helper function to set up tracing and logging
func (h StatusHandler) setupTraceAndLogger(r *http.Request, rw http.ResponseWriter) (context.Context, trace.Span, string, *slog.Logger) {
	tr := otel.Tracer(h.cfg.Server.PrefixMain)
	ctx, span := tr.Start(r.Context(), utilities.GetFunctionName())
	traceLogger := h.l.With(
		slog.String("trace_id", span.SpanContext().TraceID().String()),
		slog.String("span_id", span.SpanContext().SpanID().String()),
	)
	requestID, cl := helper.PrepareContext(r, &rw, traceLogger)

	return ctx, span, requestID, cl
}

func (eh *StatusHandler) GetStatus(w http.ResponseWriter, r *http.Request) {

	// swagger:operation GET /status Status GetStatus
	// GET - Status
	//
	// Endpoint: GET - /v1/applicationmgmt/status
	//
	//
	// Description: Returns status of ApplicationManager Instance
	//
	// ---
	// produces:
	// - application/json
	// responses:
	//   '200':
	//     description: StatusReponse
	//     schema:
	//         "$ref": "#/definitions/StatusResponse"
	//   default:
	//     description: unexpected error
	//     schema:
	//       "$ref": "#/definitions/ErrorResponse"

	// Start a trace
	ctx, span, _, cl := eh.setupTraceAndLogger(r, w)
	defer span.End()

	var response StatusResponse
	response.Status = "DOWN"
	response.Timestamp = time.Now().String()

	err := eh.pd.Ping(ctx)

	if err != nil {
		response.Status = helper.ErrorDictionary[helper.InfoDemoServerApplicationManagerStatusDOWN].Description
		response.StatusCode = helper.ErrorDictionary[helper.InfoDemoServerApplicationManagerStatusDOWN].Code

		helper.LogError(cl, helper.ErrorDatastoreNotAvailable, err, span)
	} else {
		helper.LogDebug(cl, helper.DebugDatastoreConnectionUP, helper.ErrNone, span)
		response.Status = helper.ErrorDictionary[helper.InfoDemoServerApplicationManagerStatusUP].Description
		response.StatusCode = helper.ErrorDictionary[helper.InfoDemoServerApplicationManagerStatusUP].Code
	}

	err = json.NewEncoder(w).Encode(response)

	if err != nil {
		helper.LogError(cl, helper.ErrorJSONEncodingFailed, err, span)
	}
}
