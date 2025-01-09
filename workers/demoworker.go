package workers

import (
	"DemoServer_ApplicationManager/configuration"
	"DemoServer_ApplicationManager/data"
	"DemoServer_ApplicationManager/datalayer"
	"DemoServer_ApplicationManager/handlers"
	"DemoServer_ApplicationManager/utilities"
	"context"
	"log/slog"
	"os"
	"strconv"
	"sync"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/trace"
)

type MainContext struct {
	Terminate bool
}

type Worker struct {
	l       *slog.Logger
	cfg     *configuration.Config
	pd      *datalayer.PostgresDataSource
	ah      *handlers.ApplicationHandler
	wg      *sync.WaitGroup
	mainctx *MainContext
}

func NewWorker(c *configuration.Config, l *slog.Logger, pd *datalayer.PostgresDataSource, ah *handlers.ApplicationHandler, wg *sync.WaitGroup, mainctx *MainContext) *Worker {
	return &Worker{l, c, pd, ah, wg, mainctx}
}

// Helper function to set up tracing and logging
func (w Worker) setupTraceAndLogger() (context.Context, trace.Span, *slog.Logger) {
	tr := otel.Tracer(w.cfg.Server.PrefixMain)
	ctx, span := tr.Start(context.Background(), utilities.GetFunctionName())
	traceLogger := w.l.With(
		slog.String("trace_id", span.SpanContext().TraceID().String()),
		slog.String("span_id", span.SpanContext().SpanID().String()),
	)

	return ctx, span, traceLogger
}

// start transaction
// look for first version where state == published, in running status, no lock owner and timer has expired.
// set yourself as lock owner
// and save it back to DB and commit transaction.
func (w Worker) acquireDemo(ctx context.Context) (*data.Version, error) {
	var version data.Version

	tx := w.pd.RWDB().Begin()
	if tx.Error != nil {
		return nil, tx.Error
	}

	result := w.pd.RWDB().First(
		&version,
		"state = ? AND demo_status = ? AND (lock_owner IS NULL OR lock_owner = '') AND demo_expected_end_time <= ?",
		data.Published, data.Demo_Running, time.Now(),
	)

	if result.Error != nil {
		tx.Rollback()
		return nil, result.Error
	}

	lockOwner, err := os.Hostname()
	if err != nil {
		return nil, err
	}

	version.LockOwner = lockOwner
	version.DemoStatus = data.Demo_Stopping

	utilities.UpdateObjectWithoutTx(tx, &version, ctx, w.cfg.Server.PrefixWorker)

	if err := tx.Commit().Error; err != nil {
		return nil, err
	}

	return &version, err
}

func (w Worker) updateDemoStatus(v *data.Version, status data.VersionDemoStatusTypeEnum, actualEndTime time.Time, ctx context.Context) error {
	var version data.Version

	tx := w.pd.RWDB().Begin()
	if tx.Error != nil {
		return tx.Error
	}

	v.DemoStatus = status
	v.DemoActualEndTime = actualEndTime
	v.LockOwner = ""

	utilities.UpdateObjectWithoutTx(tx, &version, ctx, w.cfg.Server.PrefixWorker)

	if err := tx.Commit().Error; err != nil {
		return err
	}

	return nil
}

func (w *Worker) ProcessDemoStatus() error {

	ctx, span, _ := w.setupTraceAndLogger()
	defer span.End()

	v, err := w.acquireDemo(ctx)

	if err != nil {
		return err
	}

	// stop the demo.
	command := "terragrunt destroy --auto-approve"
	action := data.Destroy
	err = w.ah.VersionExecIacCommandSync(v.ApplicationID.String(), strconv.Itoa(v.VersionNumber), command, action, ctx)

	if err != nil {
		if err := w.updateDemoStatus(v, data.Demo_FailedToStop, time.Time{}, ctx); err != nil {
			return err
		}
	} else {
		if err := w.updateDemoStatus(v, data.Demo_Stopped, time.Now(), ctx); err != nil {
			return err
		}
	}

	return nil
}

func (w *Worker) Work() {
	w.l.Info("DemoWorker Started")

	w.wg.Add(1)

	for {
		w.ProcessDemoStatus()

		if w.mainctx.Terminate {
			break
		}

		time.Sleep(time.Duration(w.cfg.Server.WokerSleepTime) * time.Second)
	}

	w.wg.Done()

	w.l.Info("DemoWorker Terminated")
}
