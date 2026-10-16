package policy

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestNewPolicyRejectsUnknownFields(t *testing.T) {
	// condition (singular) is not a challenge field, conditions is
	const policyYaml = `
challenges:
  preload-link:
    condition: 'true'
    runtime: preload-link
`

	t.Run("policy", func(t *testing.T) {
		_, err := NewPolicy(strings.NewReader(policyYaml))
		if err == nil || !strings.Contains(err.Error(), `unknown field "condition"`) {
			t.Fatalf("err = %v, want unknown field error", err)
		}
	})

	t.Run("snippet", func(t *testing.T) {
		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, "snippet.yml"), []byte(policyYaml), 0o644); err != nil {
			t.Fatal(err)
		}
		_, err := NewPolicy(strings.NewReader("rules: []\n"), dir)
		if err == nil || !strings.Contains(err.Error(), `unknown field "condition"`) {
			t.Fatalf("err = %v, want unknown field error", err)
		}
	})
}

func TestNewPolicyLoadsExampleSnippets(t *testing.T) {
	_, err := NewPolicy(strings.NewReader("rules: []\n"), "../../examples/snippets")
	if err != nil {
		t.Fatal(err)
	}
}
