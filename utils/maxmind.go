package utils

import (
	"fmt"
	"log/slog"
	"net"
	"os"
	"sync"
	"time"

	"github.com/oschwald/maxminddb-golang"
)

type MaxMindDB struct {
	db    *maxminddb.Reader
	mu    sync.RWMutex
	path  string
	close chan struct{}
}

type asnRecord struct {
	AutonomousSystemNumber uint `maxminddb:"autonomous_system_number"`
}

func NewMaxMindDB(path string) (*MaxMindDB, error) {
	db, err := maxminddb.Open(path)
	if err != nil {
		return nil, fmt.Errorf("failed to open MaxMind database %s: %w", path, err)
	}
	m := &MaxMindDB{db: db, path: path, close: make(chan struct{})}
	go m.watch()
	return m, nil
}

func (m *MaxMindDB) watch() {
	fi, err := os.Stat(m.path)
	if err != nil {
		slog.Error("maxmind: failed to stat database for watching", "path", m.path, "err", err)
		return
	}
	lastMod := fi.ModTime()

	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			fi, err := os.Stat(m.path)
			if err != nil {
				slog.Error("maxmind: failed to stat database", "path", m.path, "err", err)
				continue
			}
			if fi.ModTime().Equal(lastMod) {
				continue
			}
			db, err := maxminddb.Open(m.path)
			if err != nil {
				slog.Error("maxmind: failed to reload database", "path", m.path, "err", err)
				continue
			}
			m.mu.Lock()
			old := m.db
			m.db = db
			m.mu.Unlock()
			_ = old.Close()
			lastMod = fi.ModTime()
			slog.Warn("maxmind: database reloaded", "path", m.path)
		case <-m.close:
			return
		}
	}
}

func (m *MaxMindDB) Close() {
	select {
	case <-m.close:
	default:
		close(m.close)
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	_ = m.db.Close()
}

// GetASN returns the ASN number for the given IP address.
func (m *MaxMindDB) GetASN(ip net.IP) (uint, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	var record asnRecord
	err := m.db.Lookup(ip, &record)
	if err != nil {
		return 0, err
	}
	if record.AutonomousSystemNumber == 0 {
		return 0, fmt.Errorf("no ASN found for IP %s", ip)
	}
	return record.AutonomousSystemNumber, nil
}
