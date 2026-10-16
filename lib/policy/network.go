package policy

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"git.gammaspectra.live/git/go-away/utils"
	"github.com/itchyny/gojq"
	"io"
	"net"
	"net/http"
	"os"
	"regexp"
	"time"
)

type Network struct {
	// Fetches
	Url  *string `yaml:"url,omitempty"`
	File *string `yaml:"file,omitempty"`
	// Refresh re-fetches the url periodically. Files are watched for changes instead.
	Refresh time.Duration `yaml:"refresh,omitempty"`
	// RefreshJitter randomly spreads each refresh by up to ± this much. Defaults to 10% of Refresh, 0 disables it.
	RefreshJitter *time.Duration `yaml:"refresh-jitter,omitempty"`
	// ASN fetches prefixes via RADb.
	//
	// Deprecated: use a top-level asns policy entry instead.
	ASN *int `yaml:"asn,omitempty"`

	// Filtering
	JqPath *string `yaml:"jq-path,omitempty"`
	Regex  *string `yaml:"regex,omitempty"`

	Prefixes []string `yaml:"prefixes,omitempty"`
}

// MinRefresh is the shortest allowed refresh interval, to not hammer list hosts.
const MinRefresh = 5 * time.Minute

// DefaultRefreshJitter returns the jitter used when refresh-jitter is not set.
func DefaultRefreshJitter(refresh time.Duration) time.Duration {
	return refresh / 10
}

// EffectiveRefreshJitter returns the configured refresh-jitter, or the default for refresh.
func EffectiveRefreshJitter(refresh time.Duration, jitter *time.Duration) time.Duration {
	if jitter != nil {
		return *jitter
	}
	return DefaultRefreshJitter(refresh)
}

func validateRefresh(refresh time.Duration, jitter *time.Duration, url *string) error {
	if jitter != nil {
		if refresh == 0 {
			return errors.New("refresh-jitter can only be used with refresh")
		}
		if *jitter < 0 || *jitter > refresh/2 {
			return fmt.Errorf("refresh-jitter %s must be between 0 and half of refresh (%s)", *jitter, refresh/2)
		}
	}
	if refresh == 0 {
		return nil
	}
	if url == nil {
		return errors.New("refresh can only be used with url, files are watched for changes")
	}
	if refresh < MinRefresh {
		return fmt.Errorf("refresh %s is shorter than the minimum of %s", refresh, MinRefresh)
	}
	return nil
}

func (n Network) Validate() error {
	return validateRefresh(n.Refresh, n.RefreshJitter, n.Url)
}

// MaxListSize is the largest url or file list that will be read.
const MaxListSize = 32 * 1024 * 1024

func readSource(c *http.Client, url, file *string) ([]byte, error) {
	var reader io.Reader
	if url != nil {
		response, err := c.Get(*url)
		if err != nil {
			return nil, err
		}
		defer response.Body.Close()
		if response.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("unexpected status code: %d", response.StatusCode)
		}
		reader = response.Body
	} else if file != nil {
		f, err := os.Open(*file)
		if err != nil {
			return nil, err
		}
		defer f.Close()
		reader = f
	} else {
		return nil, errors.New("no url or file specified")
	}

	data, err := io.ReadAll(io.LimitReader(reader, MaxListSize+1))
	if err != nil {
		return nil, err
	}
	if len(data) > MaxListSize {
		return nil, fmt.Errorf("list is larger than %d bytes", MaxListSize)
	}
	return data, nil
}

func runJq(data []byte, jqPath string) ([]any, error) {
	var jsonData any
	err := json.Unmarshal(data, &jsonData)
	if err != nil {
		return nil, err
	}

	query, err := gojq.Parse(jqPath)
	if err != nil {
		return nil, err
	}
	var values []any
	iter := query.Run(jsonData)
	for {
		value, more := iter.Next()
		if !more {
			break
		}
		if err, ok := value.(error); ok {
			return nil, fmt.Errorf("jq-path %q: %w", jqPath, err)
		}
		values = append(values, value)
	}
	return values, nil
}

type regexMatch struct {
	line int
	// values of the required named group followed by the optional ones
	values []string
}

// runRegex returns all matches with the line they start on, for error messages.
// Optional groups missing from the regex are returned as empty strings.
func runRegex(data []byte, regex, required string, optional ...string) ([]regexMatch, error) {
	expr, err := regexp.Compile(regex)
	if err != nil {
		return nil, err
	}
	indexes := []int{expr.SubexpIndex(required)}
	if indexes[0] == -1 {
		return nil, fmt.Errorf("invalid regex %q: could not find %s named match", regex, required)
	}
	for _, name := range optional {
		indexes = append(indexes, expr.SubexpIndex(name))
	}

	var matches []regexMatch
	line, offset := 1, 0
	for _, loc := range expr.FindAllSubmatchIndex(data, -1) {
		line += bytes.Count(data[offset:loc[0]], []byte("\n"))
		offset = loc[0]

		values := make([]string, len(indexes))
		for i, index := range indexes {
			// unmatched optional groups have negative positions
			if index != -1 && loc[2*index] >= 0 {
				values[i] = string(data[loc[2*index]:loc[2*index+1]])
			}
		}
		matches = append(matches, regexMatch{line: line, values: values})
	}
	return matches, nil
}

func (n Network) FetchPrefixes(c *http.Client, whois *utils.RADb) (output []net.IPNet, err error) {

	if n.ASN != nil {
		result, err := whois.FetchASNets(*n.ASN)
		if err != nil {
			return nil, fmt.Errorf("failed to fetch ASN %d: %w", *n.ASN, err)
		}
		return result, nil
	}

	if len(n.Prefixes) > 0 {
		for _, prefix := range n.Prefixes {
			ipNet, err := parseCIDROrIP(prefix)
			if err != nil {
				return nil, err
			}
			output = append(output, ipNet)
		}
	}

	if n.Url == nil && n.File == nil {
		if len(output) > 0 {
			return output, nil
		}
		return nil, errors.New("no url, file or prefixes specified")
	}

	data, err := readSource(c, n.Url, n.File)
	if err != nil {
		return nil, err
	}

	if n.JqPath != nil {
		values, err := runJq(data, *n.JqPath)
		if err != nil {
			return nil, err
		}
		for i, value := range values {
			strValue, ok := value.(string)
			if !ok {
				return nil, fmt.Errorf("jq-path output %d: invalid value from jq-query: %v", i+1, value)
			}
			ipNet, err := parseCIDROrIP(strValue)
			if err != nil {
				return nil, fmt.Errorf("jq-path output %d: %w", i+1, err)
			}
			output = append(output, ipNet)
		}
	} else if n.Regex != nil {
		matches, err := runRegex(data, *n.Regex, "prefix")
		if err != nil {
			return nil, err
		}
		for _, match := range matches {
			ipNet, err := parseCIDROrIP(match.values[0])
			if err != nil {
				return nil, fmt.Errorf("line %d: %w", match.line, err)
			}
			output = append(output, ipNet)
		}
	} else {
		return nil, errors.New("no jq-path or regex specified")
	}
	return output, nil
}

func parseCIDROrIP(value string) (net.IPNet, error) {
	_, ipNet, err := net.ParseCIDR(value)
	if err != nil {
		ip := net.ParseIP(value)
		if ip == nil {
			return net.IPNet{}, fmt.Errorf("failed to parse CIDR: %s", err)
		}

		if ip4 := ip.To4(); ip4 != nil {
			return net.IPNet{
				IP: ip4,
				// single ip
				Mask: net.CIDRMask(len(ip4)*8, len(ip4)*8),
			}, nil
		}
		return net.IPNet{
			IP: ip,
			// single ip
			Mask: net.CIDRMask(len(ip)*8, len(ip)*8),
		}, nil
	} else if ipNet != nil {
		return *ipNet, nil
	} else {
		return net.IPNet{}, errors.New("invalid CIDR")
	}
}
