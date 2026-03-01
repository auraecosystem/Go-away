package utils

import (
	"testing"
)

func TestExactQueryParams(t *testing.T) {
	rawQuery := "svelte&type=style&lang.css"
	e, err := NewExactQueryParams(rawQuery)
	if err != nil {
		t.Fatalf("Error parsing raw url %v", err)
	}

	if e.GetRaw() != rawQuery {
		t.Errorf("Expected raw query to be '%s', got '%s'", rawQuery, e.GetRaw())
	}

	keys := []string{"svelte", "type", "lang.css"}
	expectedValues := []struct {
		value string
		found bool
	}{{"", true}, {"style", true}, {"", true}}
	if len(e) != len(keys) {
		t.Errorf("Expected %d query params, got %d", len(keys), len(e))
	}
	for i, key := range keys {
		if !e.Has(key) {
			t.Errorf("Expected to find '%s' in query params", key)
		}
		value, found := e.Get(key)

		if value != expectedValues[i].value || found != expectedValues[i].found {
			t.Errorf("Expected to find '%s' in query params, got '%s'", expectedValues[i].value, expectedValues[i].value)
		}
	}

	expectedRawValues := []string{"type=style&lang.css", "lang.css", ""}
	for i, key := range keys {
		e.Del(key)
		if e.GetRaw() != expectedRawValues[i] {
			t.Errorf("Expected raw query to be '%s', got '%s'", expectedRawValues[i], e.GetRaw())
		}
	}

	e, err = NewExactQueryParams(rawQuery)
	if err != nil {
		t.Fatalf("Error parsing raw url %v", err)
	}
	e.Set("svelte", "yes")
	if e.GetRaw() != "svelte=yes&type=style&lang.css" {
		t.Errorf("Expected raw query to be '%s', got '%s'", "svelte=yes&type=style&lang.css", e.GetRaw())
	}
	e.Set("svelte", "")
	if e.GetRaw() != "svelte=&type=style&lang.css" {
		t.Errorf("Expected raw query to be '%s', got '%s'", "svelte=&type=style&lang.css", e.GetRaw())
	}

	e.Set("non-existing", "now%20with%20value")
	if e.GetRaw() != "svelte=&type=style&lang.css&non-existing=now%20with%20value" {
		t.Errorf("Expected raw query to be '%s', got '%s'", "svelte=&type=style&lang.css&non-existing=now%20with%20value", e.GetRaw())
	}

	rawQuery = "svelte&type=style&lang.css&type=another"
	e, err = NewExactQueryParams(rawQuery)
	if err != nil {
		t.Fatalf("Error parsing raw url %v", err)
	}
	if e.GetRaw() != rawQuery {
		t.Errorf("Expected raw query to be '%s', got '%s'", rawQuery, e.GetRaw())
	}
	e.Set("type", "new-type")
	if e.GetRaw() != "svelte&type=new-type&lang.css" {
		t.Errorf("Expected raw query to be '%s', got '%s'", "svelte&type=new-type&lang.css", e.GetRaw())
	}

	e.Add("type2", "value2")
	if e.GetRaw() != "svelte&type=new-type&lang.css&type2=value2" {
		t.Errorf("Expected raw query to be '%s', got '%s'", "svelte&type=new-type&lang.css&type2=value2", e.GetRaw())
	}

	e.DelPrefix("typ")
	if e.GetRaw() != "svelte&lang.css" {
		t.Errorf("Expected raw query to be '%s', got '%s'", "svelte&lang.css", e.GetRaw())
	}
}
