package cli

import (
	"os"
	"strings"
	"testing"
)

// captureStderr runs fn with os.Stderr redirected to a pipe and returns what it
// wrote.
func captureStderr(t *testing.T, fn func()) string {
	t.Helper()

	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe: %v", err)
	}
	old := os.Stderr
	os.Stderr = w

	done := make(chan string, 1)
	go func() {
		var sb strings.Builder
		buf := make([]byte, 4096)
		for {
			n, err := r.Read(buf)
			if n > 0 {
				sb.Write(buf[:n])
			}
			if err != nil {
				break
			}
		}
		done <- sb.String()
	}()

	fn()

	os.Stderr = old
	_ = w.Close()
	out := <-done
	_ = r.Close()

	return out
}

func TestResolveProgressModeHonoursExplicitPreferences(t *testing.T) {
	cases := []struct {
		preference string
		want       progressMode
	}{
		{"none", progressOff},
		{"NONE", progressOff},
		{"  none  ", progressOff},
		{"tty", progressTTY},
		{"plain", progressPlain},
	}

	for _, tc := range cases {
		if got := resolveProgressMode(tc.preference); got != tc.want {
			t.Errorf("resolveProgressMode(%q) = %v, want %v", tc.preference, got, tc.want)
		}
	}
}

func TestResolveProgressModeFallsBackToPlainWithoutATTY(t *testing.T) {
	// Arrange: go test runs with stderr redirected, so auto must not pick TTY.
	// Guard anyway, so the test still means something under a TTY-attached run.
	if isStderrTerminal() {
		t.Skip("stderr is a terminal; auto-detection cannot be exercised here")
	}

	// Act & Assert
	if got := resolveProgressMode("auto"); got != progressPlain {
		t.Errorf("resolveProgressMode(\"auto\") = %v with no TTY, want progressPlain", got)
	}
	if got := resolveProgressMode(""); got != progressPlain {
		t.Errorf("resolveProgressMode(\"\") = %v with no TTY, want progressPlain", got)
	}
}

func TestValidateProgressPreference(t *testing.T) {
	for _, ok := range []string{"auto", "tty", "plain", "none", "AUTO", " plain "} {
		if err := validateProgressPreference(ok); err != nil {
			t.Errorf("validateProgressPreference(%q) = %v, want nil", ok, err)
		}
	}
	for _, bad := range []string{"bar", "yes", "1", "quiet"} {
		if err := validateProgressPreference(bad); err == nil {
			t.Errorf("validateProgressPreference(%q) = nil, want an error", bad)
		}
	}
}

func TestPlainProgressWritesAppendOnlyLines(t *testing.T) {
	// Arrange
	setProgressMode(progressPlain)
	defer setProgressMode(progressOff)

	// Act
	out := captureStderr(t, func() {
		p := newProgress("url-override", 40)
		for range 40 {
			p.done()
		}
		p.finish()
	})

	// Assert: no ANSI escapes and no carriage returns, so logs stay readable.
	if strings.Contains(out, "\r") || strings.Contains(out, "\033") {
		t.Errorf("plain progress must not emit carriage returns or escape codes, got %q", out)
	}
	if !strings.Contains(out, "[progress] url-override: 40 requests") {
		t.Errorf("expected a start line, got %q", out)
	}
	for _, milestone := range []string{"25%", "50%", "75%"} {
		if !strings.Contains(out, milestone) {
			t.Errorf("expected a %s milestone line, got %q", milestone, out)
		}
	}
	if !strings.Contains(out, "done 40/40") {
		t.Errorf("expected a completion line, got %q", out)
	}
}

func TestPlainProgressSkipsMilestonesForSmallTechniques(t *testing.T) {
	// Arrange
	setProgressMode(progressPlain)
	defer setProgressMode(progressOff)

	// Act
	out := captureStderr(t, func() {
		p := newProgress("url-override", plainMilestoneMin-1)
		for range plainMilestoneMin - 1 {
			p.done()
		}
		p.finish()
	})

	// Assert: start and done only — intermediate lines would just be noise.
	if strings.Contains(out, "%") {
		t.Errorf("small techniques should not emit milestone lines, got %q", out)
	}
	if !strings.Contains(out, "done") {
		t.Errorf("expected a completion line, got %q", out)
	}
}

func TestPlainProgressEmitsEachMilestoneOnce(t *testing.T) {
	// Arrange
	setProgressMode(progressPlain)
	defer setProgressMode(progressOff)

	// Act
	out := captureStderr(t, func() {
		p := newProgress("headers", 100)
		for range 100 {
			p.done()
		}
		p.finish()
	})

	// Assert
	if got := strings.Count(out, "50%"); got != 1 {
		t.Errorf("50%% milestone emitted %d times, want exactly 1: %q", got, out)
	}
}

func TestProgressOffWritesNothing(t *testing.T) {
	// Arrange
	setProgressMode(progressOff)

	// Act
	out := captureStderr(t, func() {
		p := newProgress("headers", 50)
		for range 50 {
			p.done()
		}
		p.finish()
	})

	// Assert
	if out != "" {
		t.Errorf("progress none must be silent, got %q", out)
	}
}

func TestZeroTotalProgressWritesNothing(t *testing.T) {
	// Arrange: techniques that find no payloads pass a zero total.
	setProgressMode(progressPlain)
	defer setProgressMode(progressOff)

	// Act
	out := captureStderr(t, func() {
		p := newProgress("endpaths", 0)
		p.done()
		p.finish()
	})

	// Assert
	if out != "" {
		t.Errorf("a zero-total tracker must be silent, got %q", out)
	}
}
