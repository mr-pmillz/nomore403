// SPDX-License-Identifier: MIT

package nomore403

import (
	"os"
	"path/filepath"
	"slices"
	"testing"
)

func TestPayloadNamesCoversEveryWordlist(t *testing.T) {
	// Arrange
	want := []string{"endpaths", "headers", "httpmethods", "ips", "midpaths", "simpleheaders", "useragents"}

	// Act
	got, err := PayloadNames()

	// Assert
	if err != nil {
		t.Fatalf("PayloadNames() error: %v", err)
	}
	if !slices.Equal(got, want) {
		t.Fatalf("PayloadNames() = %v, want %v", got, want)
	}
}

func TestPayloadLinesReadsEmbeddedListWhenNoDirGiven(t *testing.T) {
	// Arrange
	names, err := PayloadNames()
	if err != nil {
		t.Fatalf("PayloadNames() error: %v", err)
	}

	// Act & Assert
	for _, name := range names {
		lines, err := PayloadLines("", name)
		if err != nil {
			t.Fatalf("PayloadLines(%q) error: %v", name, err)
		}
		if len(lines) == 0 {
			t.Fatalf("embedded payload list %q is empty", name)
		}
		for i, line := range lines {
			if line == "" {
				t.Fatalf("payload list %q line %d is empty", name, i)
			}
		}
	}
}

func TestPayloadLinesPrefersDirectoryOverEmbedded(t *testing.T) {
	// Arrange
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "headers"), []byte("X-Only-Mine\r\n\n"), 0o600); err != nil {
		t.Fatalf("write override: %v", err)
	}

	// Act
	got, err := PayloadLines(dir, "headers")

	// Assert
	if err != nil {
		t.Fatalf("PayloadLines error: %v", err)
	}
	if !slices.Equal(got, []string{"X-Only-Mine"}) {
		t.Fatalf("PayloadLines = %v, want [X-Only-Mine] (CRLF trimmed, blanks dropped)", got)
	}
}

func TestPayloadLinesFallsBackToEmbeddedForListsMissingFromDirectory(t *testing.T) {
	// Arrange: a directory that overrides only "headers".
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "headers"), []byte("X-Only-Mine\n"), 0o600); err != nil {
		t.Fatalf("write override: %v", err)
	}
	embedded, err := PayloadLines("", "ips")
	if err != nil {
		t.Fatalf("PayloadLines(embedded ips) error: %v", err)
	}

	// Act
	got, err := PayloadLines(dir, "ips")

	// Assert
	if err != nil {
		t.Fatalf("PayloadLines error: %v", err)
	}
	if !slices.Equal(got, embedded) {
		t.Fatalf("PayloadLines(dir, \"ips\") = %v, want the embedded list %v", got, embedded)
	}
}

func TestPayloadLinesReturnsErrorForUnknownList(t *testing.T) {
	// Act
	_, err := PayloadLines("", "does-not-exist")

	// Assert
	if err == nil {
		t.Fatal("PayloadLines(\"\", \"does-not-exist\") = nil error, want an error")
	}
}

func TestRandomPayloadLineReturnsAnEntryFromTheList(t *testing.T) {
	// Arrange
	agents, err := PayloadLines("", "useragents")
	if err != nil {
		t.Fatalf("PayloadLines error: %v", err)
	}

	// Act & Assert
	for range 20 {
		got, err := RandomPayloadLine("", "useragents")
		if err != nil {
			t.Fatalf("RandomPayloadLine error: %v", err)
		}
		if !slices.Contains(agents, got) {
			t.Fatalf("RandomPayloadLine returned %q, which is not in the useragents list", got)
		}
	}
}

func TestBuildInfoDefaultsToDevelopmentValues(t *testing.T) {
	// Act
	v, c, d := BuildInfo()

	// Assert: an un-stamped test build reports the ldflags defaults.
	if v != Version() {
		t.Fatalf("BuildInfo version %q != Version() %q", v, Version())
	}
	if v == "" || c == "" || d == "" {
		t.Fatalf("BuildInfo() = (%q, %q, %q), want all fields populated", v, c, d)
	}
}
