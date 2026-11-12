package rz

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

// maxAuditLineBytes is the largest single JSONL audit line the reader accepts.
const maxAuditLineBytes = 1 << 20

// AuditStore is an append-only structured JSON audit log (JSONL).
// Every entry from every actor/decision lands here.
//
// Tamper-evidence: Append chains each entry to the previous one by computing
// prevHash + hash BEFORE writing, so the log is a hash chain.
type AuditStore struct {
	mu       sync.Mutex
	f        string
	claimed  map[string]bool
	hydrated bool
}

// NewAuditStore creates (or opens) the JSONL audit log at logFile.
// An empty logFile defaults to data/audit.log.jsonl under the working dir.
func NewAuditStore(logFile string) (*AuditStore, error) {
	if logFile == "" {
		logFile = filepath.Join("data", "audit.log.jsonl")
	}
	if err := os.MkdirAll(filepath.Dir(logFile), 0o755); err != nil {
		return nil, err
	}
	return &AuditStore{f: logFile}, nil
}

func (s *AuditStore) Path() string { return s.f }

// Append hashes and writes one entry.
func (s *AuditStore) Append(e AuditEntry) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	prevHash, err := readLastHash(s.f)
	if err != nil {
		return err
	}
	if prevHash == "" {
		prevHash = GenesisHash
	}
	entry := e
	entry.PrevHash = prevHash
	entry.Hash = ComputeHash(prevHash, &e)
	line, err := json.Marshal(entry)
	if err != nil {
		return err
	}
	f, err := os.OpenFile(s.f, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = f.Write(append(line, '\n'))
	if err == nil && BroadcastHub != nil {
		BroadcastHub.Broadcast(entry)
	}
	return err
}

// All returns every stored entry in order.
func (s *AuditStore) All() ([]AuditEntry, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return readAllEntries(s.f)
}

// Claim is an atomic "at-most-once" reservation for an event ID. It returns
// true exactly once per event ID for the lifetime of the store (including IDs
// already present in the log when the store is opened, so a restarted process
// still refuses to re-execute them). The check-and-mark are serialized by the
// store mutex, which makes concurrent duplicate deliveries safe: exactly one
// caller wins, every other caller is told the event was already processed.
func (s *AuditStore) Claim(eventID string) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.hydrateLocked(); err != nil {
		return false, err
	}
	if s.claimed[eventID] {
		return false, nil
	}
	s.claimed[eventID] = true
	return true, nil
}

// hydrateLocked rebuilds the claimed set from the persisted log once.
func (s *AuditStore) hydrateLocked() error {
	if s.hydrated {
		return nil
	}
	if s.claimed == nil {
		s.claimed = map[string]bool{}
	}
	entries, err := readAllEntries(s.f)
	if err != nil {
		return err
	}
	for _, e := range entries {
		s.claimed[e.EventID] = true
	}
	s.hydrated = true
	return nil
}

// Clear removes the log file.
func (s *AuditStore) Clear() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	err := os.Remove(s.f)
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	s.claimed = nil
	s.hydrated = false
	return nil
}

// ReadAuditFile reads ALL entries from a JSONL audit file (for verification
// CLIs that don't hold a store handle). Returns an error if the file is absent.
func ReadAuditFile(file string) ([]AuditEntry, error) {
	entries, err := readAllEntries(file)
	if err != nil {
		return nil, err
	}
	if len(entries) == 0 && fileExists(file) == false {
		return nil, os.ErrNotExist
	}
	return entries, nil
}

func fileExists(name string) bool {
	_, err := os.Stat(name)
	return err == nil
}

// readLastHash reads just the last entry's hash (the chain tail).
func readLastHash(file string) (string, error) {
	entries, err := readAllEntries(file)
	if err != nil {
		return "", err
	}
	if len(entries) == 0 {
		return "", nil
	}
	return entries[len(entries)-1].Hash, nil
}

func readAllEntries(file string) ([]AuditEntry, error) {
	f, err := os.Open(file)
	if err != nil {
		if os.IsNotExist(err) {
			return []AuditEntry{}, nil
		}
		return nil, err
	}
	defer f.Close()
	var out []AuditEntry
	sc := bufio.NewScanner(f)
	// The default 64 KB token limit would make the whole log unreadable after a
	// single long entry; allow lines up to maxAuditLineBytes.
	sc.Buffer(make([]byte, 0, 64*1024), maxAuditLineBytes)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		var e AuditEntry
		if err := json.Unmarshal([]byte(line), &e); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, sc.Err()
}
