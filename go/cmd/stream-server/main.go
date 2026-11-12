package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"razor_gateway/go/rz"
)

func main() {
	port := flag.String("port", "8090", "HTTP/SSE server port (the PORT env var overrides this)")
	auditPath := flag.String("audit", filepath.Join(rz.DefaultWorkDir, "audit.log.jsonl"), "audit log file to serve")
	flowsDir := flag.String("flows", filepath.Join(rz.DefaultWorkDir, "flows"), "directory of flow events (*.json)")
	workDir := flag.String("workdir", rz.DefaultWorkDir, "scratch directory for compare-policy / sandbox logs")
	seed := flag.Bool("seed", false, "if the audit log is empty, run the batch into it before serving")
	flag.Parse()
	if v := os.Getenv("PORT"); v != "" {
		*port = v
	}

	if err := run(*port, *auditPath, *flowsDir, *workDir, *seed); err != nil {
		fmt.Fprintln(os.Stderr, "stream-server:", err)
		os.Exit(1)
	}
}

func run(port, auditPath, flowsDir, workDir string, seed bool) error {
	audit, err := rz.NewAuditStore(auditPath)
	if err != nil {
		return fmt.Errorf("open audit log %s: %w", auditPath, err)
	}

	// A missing flows directory is not fatal: the stream, metrics and chain
	// endpoints still work; only the compute endpoints need the batch.
	events, err := rz.LoadEvents(flowsDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "stream-server: no events loaded from %s (%v); compute endpoints disabled\n", flowsDir, err)
		events = nil
	}

	if seed {
		if err := seedIfEmpty(audit, events); err != nil {
			return err
		}
	}

	hub := rz.NewStreamHub()
	rz.BroadcastHub = hub
	opts := rz.StreamServerOptions{Events: events, WorkDir: workDir}
	if _, err := rz.StartStreamServerWithOptions(audit, hub, ":"+port, opts); err != nil {
		return err
	}

	fmt.Printf("stream-server listening on :%s\n", port)
	select {}
}

// seedIfEmpty runs the batch into an empty audit log so a fresh deployment has
// data to show. An existing log is never touched.
func seedIfEmpty(audit *rz.AuditStore, events []*rz.FlowEvent) error {
	existing, err := audit.All()
	if err != nil {
		return fmt.Errorf("read audit log: %w", err)
	}
	if len(existing) > 0 {
		return nil
	}
	if len(events) == 0 {
		return fmt.Errorf("-seed needs flow events, but none were loaded")
	}
	if _, err := rz.RunBatch(events, audit, rz.RunnerOpts{Now: rz.BatchNow()}); err != nil {
		return fmt.Errorf("seed batch: %w", err)
	}
	fmt.Printf("seeded audit log with the %d-event batch\n", len(events))
	return nil
}
