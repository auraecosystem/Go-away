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

type countryRecord struct {
	Country struct {
		IsoCode string `maxminddb:"iso_code"`
	} `maxminddb:"country"`
	RegisteredCountry struct {
		IsoCode string `maxminddb:"iso_code"`
	} `maxminddb:"registered_country"`
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

// GetCountry returns the ISO 3166-1 alpha-2 country code for the given IP address,
// falling back to the registered country when no location country is known.
// An empty string is returned when the database has no country for the IP.
func (m *MaxMindDB) GetCountry(ip net.IP) (string, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	var record countryRecord
	err := m.db.Lookup(ip, &record)
	if err != nil {
		return "", err
	}
	if record.Country.IsoCode != "" {
		return record.Country.IsoCode, nil
	}
	return record.RegisteredCountry.IsoCode, nil
}
