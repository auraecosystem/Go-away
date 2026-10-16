package policy

import (
	"errors"
	"fmt"
	"git.gammaspectra.live/git/go-away/utils"
	"math"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"
)

const (
	LookupMethodRADb    = ""
	LookupMethodMaxMind = "maxmind"
)

// ASNEntry is either a single ASN, or a list of ASNs loaded from a url or file.
// By default, a single ASN gets its prefixes pre-fetched via RADb.
// Set lookup_method to "maxmind" to perform per-request ASN lookup via MaxMind at runtime instead.
// Lists (url or file) are only supported with lookup_method "maxmind", to avoid flooding RADb with queries.
type ASNEntry struct {
	ASN     *int   `yaml:"asn,omitempty"`
	Comment string `yaml:"comment,omitempty"`

	// List fetches
	Url  *string `yaml:"url,omitempty"`
	File *string `yaml:"file,omitempty"`
	// Refresh re-fetches the url periodically. Files are watched for changes instead.
	Refresh time.Duration `yaml:"refresh,omitempty"`
	// RefreshJitter randomly spreads each refresh by up to ± this much. Defaults to 10% of Refresh, 0 disables it.
	RefreshJitter *time.Duration `yaml:"refresh-jitter,omitempty"`

	// List filtering, exactly one is required for lists.
	// A regex must have an "asn" named match, and can have a "comment" one.
	// A jq-path must output ASNs as numbers, strings, or {"asn": ..., "comment": ...} objects.
	JqPath *string `yaml:"jq-path,omitempty"`
	Regex  *string `yaml:"regex,omitempty"`

	LookupMethod string `yaml:"lookup_method,omitempty"`
}

// ASNRecord is a resolved ASN, with an optional comment used in logs.
type ASNRecord struct {
	ASN     uint
	Comment string
}

// IsList reports whether the entry loads its ASNs from a url or file.
func (a ASNEntry) IsList() bool {
	return a.Url != nil || a.File != nil
}

// Source describes where the entry's ASNs come from, for logging.
func (a ASNEntry) Source() string {
	switch {
	case a.ASN != nil:
		return "AS" + strconv.Itoa(*a.ASN)
	case a.Url != nil:
		return *a.Url
	case a.File != nil:
		return *a.File
	}
	return "<empty>"
}

func (a ASNEntry) Validate() error {
	sources := 0
	for _, set := range []bool{a.ASN != nil, a.Url != nil, a.File != nil} {
		if set {
			sources++
		}
	}
	if sources != 1 {
		return errors.New("exactly one of asn, url or file must be specified")
	}

	switch a.LookupMethod {
	case LookupMethodRADb, LookupMethodMaxMind:
	default:
		return fmt.Errorf("unknown lookup_method %q", a.LookupMethod)
	}

	if err := validateRefresh(a.Refresh, a.RefreshJitter, a.Url); err != nil {
		return err
	}

	if a.ASN != nil {
		if a.JqPath != nil || a.Regex != nil {
			return errors.New("jq-path and regex can only be used with url or file")
		}
		_, err := toASN(int64(*a.ASN))
		return err
	}

	if a.Comment != "" {
		return errors.New("comment can only be used with asn, list comments come from the list itself")
	}
	if a.LookupMethod != LookupMethodMaxMind {
		return fmt.Errorf("url and file lists require lookup_method %q", LookupMethodMaxMind)
	}
	if (a.JqPath == nil) == (a.Regex == nil) {
		return errors.New("url and file lists require exactly one of jq-path or regex")
	}
	return nil
}

// Resolve returns the single configured ASN, or loads and parses the ASN list.
func (a ASNEntry) Resolve(c *http.Client) ([]ASNRecord, error) {
	if a.ASN != nil {
		asn, err := toASN(int64(*a.ASN))
		if err != nil {
			return nil, err
		}
		return []ASNRecord{{ASN: asn, Comment: a.Comment}}, nil
	}

	data, err := readSource(c, a.Url, a.File)
	if err != nil {
		return nil, err
	}
	return ParseASNList(data, a.JqPath, a.Regex)
}

func (a ASNEntry) FetchPrefixes(whois *utils.RADb) ([]net.IPNet, error) {
	if a.ASN == nil {
		return nil, errors.New("only single asn entries can be fetched from RADb")
	}
	result, err := whois.FetchASNets(*a.ASN)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch ASN %d from RADb: %w", *a.ASN, err)
	}
	return result, nil
}

// ParseASNList extracts ASNs from data using jqPath if set, otherwise regex.
func ParseASNList(data []byte, jqPath, regex *string) (output []ASNRecord, err error) {
	if jqPath != nil {
		values, err := runJq(data, *jqPath)
		if err != nil {
			return nil, err
		}
		for i, value := range values {
			var record ASNRecord
			if obj, ok := value.(map[string]any); ok {
				record.ASN, err = jqToASN(obj["asn"])
				if comment, ok := obj["comment"]; ok && comment != nil {
					if s, ok := comment.(string); ok {
						record.Comment = s
					} else {
						err = fmt.Errorf("invalid comment from jq-query: %v", comment)
					}
				}
			} else {
				record.ASN, err = jqToASN(value)
			}
			if err != nil {
				return nil, fmt.Errorf("jq-path output %d: %w", i+1, err)
			}
			output = append(output, record)
		}
		return output, nil
	}

	if regex == nil {
		return nil, errors.New("no jq-path or regex specified")
	}
	matches, err := runRegex(data, *regex, "asn", "comment")
	if err != nil {
		return nil, err
	}
	for _, match := range matches {
		asn, err := parseASN(match.values[0])
		if err != nil {
			return nil, fmt.Errorf("line %d: %w", match.line, err)
		}
		output = append(output, ASNRecord{ASN: asn, Comment: strings.TrimSpace(match.values[1])})
	}
	return output, nil
}

func jqToASN(value any) (uint, error) {
	switch v := value.(type) {
	case string:
		return parseASN(v)
	case int:
		return toASN(int64(v))
	case float64:
		if v != math.Trunc(v) {
			return 0, fmt.Errorf("invalid ASN from jq-query: %v", v)
		}
		return toASN(int64(v))
	}
	return 0, fmt.Errorf("invalid ASN from jq-query: %v", value)
}

func parseASN(value string) (uint, error) {
	value = strings.TrimSpace(value)
	if len(value) > 2 && strings.EqualFold(value[:2], "AS") {
		value = value[2:]
	}
	n, err := strconv.ParseInt(value, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("invalid ASN %q", value)
	}
	return toASN(n)
}

func toASN(n int64) (uint, error) {
	if n <= 0 || n > math.MaxUint32 {
		return 0, fmt.Errorf("ASN %d out of range", n)
	}
	return uint(n), nil
}
