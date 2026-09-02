// SPDX-License-Identifier: MIT

package nomore403

import (
	"embed"
	"errors"
	"fmt"
	"io/fs"
	"math/rand"
	"os"
	"sort"
	"strings"
)

// payloadsRoot is the directory inside the embedded filesystem that holds the
// wordlists. It matches the on-disk layout so a custom -f directory can use the
// same file names.
const payloadsRoot = "payloads"

// embeddedPayloads carries every wordlist into the binary so nomore403 runs
// stand-alone, from any working directory, with no payloads/ folder alongside
// it.
//
//go:embed payloads
var embeddedPayloads embed.FS

// PayloadNames returns the sorted names of the wordlists compiled into the
// binary.
func PayloadNames() ([]string, error) {
	entries, err := fs.ReadDir(embeddedPayloads, payloadsRoot)
	if err != nil {
		return nil, fmt.Errorf("reading embedded payloads: %w", err)
	}

	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		names = append(names, entry.Name())
	}
	sort.Strings(names)

	return names, nil
}

// PayloadLines returns the non-empty lines of the named wordlist.
//
// When dir is empty the embedded copy is used. When dir is set (the -f flag)
// the file is read from that directory instead, falling back to the embedded
// copy when the directory does not carry that particular list. This lets an
// operator override one wordlist without having to supply all of them.
func PayloadLines(dir, name string) ([]string, error) {
	data, err := payloadBytes(dir, name)
	if err != nil {
		return nil, err
	}

	return splitPayloadLines(data), nil
}

// RandomPayloadLine returns a uniformly random entry from the named wordlist.
// Resolution follows the same disk-then-embedded order as PayloadLines.
func RandomPayloadLine(dir, name string) (string, error) {
	lines, err := PayloadLines(dir, name)
	if err != nil {
		return "", err
	}
	if len(lines) == 0 {
		return "", fmt.Errorf("no entries found in payload list %q", name)
	}

	// Picking a User-Agent to blend in with; unpredictability is not required.
	return lines[rand.Intn(len(lines))], nil //nolint:gosec // G404: wordlist selection, not a security decision
}

// payloadBytes resolves a wordlist to its raw bytes, preferring an operator
// supplied directory over the embedded copy.
func payloadBytes(dir, name string) ([]byte, error) {
	if dir != "" {
		// os.DirFS confines the read to dir and rejects traversal in name.
		data, err := fs.ReadFile(os.DirFS(dir), name)
		if err == nil {
			return data, nil
		}
		if !errors.Is(err, fs.ErrNotExist) {
			return nil, fmt.Errorf("reading payload list %q from %s: %w", name, dir, err)
		}
		// Not in the custom directory: fall through to the embedded copy.
	}

	data, err := fs.ReadFile(embeddedPayloads, payloadsRoot+"/"+name)
	if err != nil {
		return nil, fmt.Errorf("reading embedded payload list %q: %w", name, err)
	}

	return data, nil
}

// splitPayloadLines splits wordlist bytes into lines, dropping empty ones and
// tolerating CRLF endings.
func splitPayloadLines(data []byte) []string {
	raw := strings.Split(string(data), "\n")

	lines := make([]string, 0, len(raw))
	for _, line := range raw {
		line = strings.TrimRight(line, "\r")
		if line == "" {
			continue
		}
		lines = append(lines, line)
	}

	return lines
}
