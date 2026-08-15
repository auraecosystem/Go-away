package policy

import (
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
)

type Network struct {
	// Fetches
	Url  *string `yaml:"url,omitempty"`
	File *string `yaml:"file,omitempty"`
	// ASN fetches prefixes via RADb.
	//
	// Deprecated: use a top-level asns policy entry instead.
	ASN *int `yaml:"asn,omitempty"`

	// Filtering
	JqPath *string `yaml:"jq-path,omitempty"`
	Regex  *string `yaml:"regex,omitempty"`

	Prefixes []string `yaml:"prefixes,omitempty"`
}

// ASNEntry resolves an ASN number to its IP prefixes.
// Default (empty) pre-fetches prefixes via RADb at startup.
// Set lookup_method to "maxmind" to perform per-request ASN lookup via MaxMind at runtime instead.
type ASNEntry struct {
	ASN          int    `yaml:"asn"`
	LookupMethod string `yaml:"lookup_method,omitempty"`
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

	var reader io.Reader
	if n.Url != nil {
		response, err := c.Get(*n.Url)
		if err != nil {
			return nil, err
		}
		defer response.Body.Close()
		if response.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("unexpected status code: %d", response.StatusCode)
		}
		reader = response.Body
	} else if n.File != nil {
		file, err := os.Open(*n.File)
		if err != nil {
			return nil, err
		}
		defer file.Close()
		reader = file
	} else {
		if len(output) > 0 {
			return output, nil
		}
		return nil, errors.New("no url, file or prefixes specified")
	}

	data, err := io.ReadAll(reader)
	if err != nil {
		return nil, err
	}

	if n.JqPath != nil {
		var jsonData any
		err = json.Unmarshal(data, &jsonData)
		if err != nil {
			return nil, err
		}

		query, err := gojq.Parse(*n.JqPath)
		if err != nil {
			return nil, err
		}
		iter := query.Run(jsonData)
		for {
			value, more := iter.Next()
			if !more {
				break
			}

			if strValue, ok := value.(string); ok {
				ipNet, err := parseCIDROrIP(strValue)
				if err != nil {
					return nil, err
				}
				output = append(output, ipNet)
			} else {
				return nil, fmt.Errorf("invalid value from jq-query: %v", value)
			}
		}
		return output, nil
	} else if n.Regex != nil {
		expr, err := regexp.Compile(*n.Regex)
		if err != nil {
			return nil, err
		}
		prefixName := expr.SubexpIndex("prefix")
		if prefixName == -1 {
			return nil, fmt.Errorf("invalid regex %q: could not find prefix named match", *n.Regex)
		}
		matches := expr.FindAllSubmatch(data, -1)
		for _, match := range matches {
			matchName := string(match[prefixName])
			ipNet, err := parseCIDROrIP(matchName)
			if err != nil {
				return nil, err
			}
			output = append(output, ipNet)
		}
	} else {
		return nil, errors.New("no jq-path or regex specified")
	}
	return output, nil
}

func (a ASNEntry) FetchPrefixes(whois *utils.RADb) ([]net.IPNet, error) {
	result, err := whois.FetchASNets(a.ASN)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch ASN %d from RADb: %w", a.ASN, err)
	}
	return result, nil
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
