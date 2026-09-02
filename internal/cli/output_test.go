package cli

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestReadURLsFromInput_SingleURL(t *testing.T) {
	urls := readURLsFromInput("https://example.com/admin")
	if len(urls) != 1 || urls[0] != "https://example.com/admin" {
		t.Fatalf("expected single URL, got: %v", urls)
	}
}

func TestReadURLsFromInput_FileInput(t *testing.T) {
	dir := t.TempDir()
	filePath := filepath.Join(dir, "urls.txt")
	content := "https://example.com/admin\nhttps://example.com/secret\n# comment\n\nhttps://example.com/api\n"
	if err := os.WriteFile(filePath, []byte(content), 0o600); err != nil {
		t.Fatalf("write file: %v", err)
	}

	urls := readURLsFromInput(filePath)
	if len(urls) != 3 {
		t.Fatalf("expected 3 URLs, got %d: %v", len(urls), urls)
	}
	if urls[0] != "https://example.com/admin" {
		t.Errorf("url[0] = %q, want https://example.com/admin", urls[0])
	}
	if urls[2] != "https://example.com/api" {
		t.Errorf("url[2] = %q, want https://example.com/api", urls[2])
	}
}

func TestReadURLsFromInput_NonExistentFile(t *testing.T) {
	// A non-URL, non-file input should be returned as-is
	urls := readURLsFromInput("not-a-url-or-file")
	if len(urls) != 1 || urls[0] != "not-a-url-or-file" {
		t.Fatalf("expected input returned as-is, got: %v", urls)
	}
}

func TestOutputWriter_PlainText(t *testing.T) {
	dir := t.TempDir()
	outPath := filepath.Join(dir, "output.txt")

	if err := initOutputWriter(outPath); err != nil {
		t.Fatalf("initOutputWriter: %v", err)
	}

	writeResultToOutput(Result{line: "GET /admin", statusCode: 200, contentLength: 1234}, "verb-tampering")
	writeResultToOutput(Result{line: "X-Forwarded-For: 127.0.0.1", statusCode: 403, contentLength: 500}, "headers")

	closeOutputWriter()

	data, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatalf("read output: %v", err)
	}

	content := string(data)
	if !strings.Contains(content, "200") || !strings.Contains(content, "GET /admin") {
		t.Errorf("expected first result in output, got: %s", content)
	}
	if !strings.Contains(content, "403") || !strings.Contains(content, "X-Forwarded-For") {
		t.Errorf("expected second result in output, got: %s", content)
	}
}

func TestOutputWriter_JSON(t *testing.T) {
	dir := t.TempDir()
	outPath := filepath.Join(dir, "output.json")

	// Enable JSON mode
	oldJSON := jsonOutput
	jsonOutput = true
	defer func() { jsonOutput = oldJSON }()

	// Reset jsonResults
	jsonResultsMutex.Lock()
	jsonResults = nil
	jsonResultsMutex.Unlock()

	if err := initOutputWriter(outPath); err != nil {
		t.Fatalf("initOutputWriter: %v", err)
	}

	writeResultToOutput(Result{line: "GET /admin", statusCode: 200, contentLength: 1234, score: 90, likelihood: "high", reproCurl: "curl ..."}, "verb-tampering")
	writeResultToOutput(Result{line: "X-Forwarded-For: 127.0.0.1", statusCode: 403, contentLength: 500, score: 20, likelihood: "low"}, "headers")

	closeOutputWriter()

	data, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatalf("read output: %v", err)
	}

	var results []JSONResult
	if err := json.Unmarshal(data, &results); err != nil {
		t.Fatalf("unmarshal JSON: %v (content: %s)", err, string(data))
	}

	if len(results) != 2 {
		t.Fatalf("expected 2 results, got %d", len(results))
	}

	if results[0].StatusCode != 200 || results[0].Technique != "verb-tampering" {
		t.Errorf("unexpected first result: %+v", results[0])
	}
	if results[0].Score != 90 || results[0].Likelihood != "high" || results[0].ReproCurl != "curl ..." {
		t.Errorf("expected enriched fields in first result, got %+v", results[0])
	}
	if results[1].StatusCode != 403 || results[1].Technique != "headers" {
		t.Errorf("unexpected second result: %+v", results[1])
	}
}

func TestOutputWriter_JSONL(t *testing.T) {
	dir := t.TempDir()
	outPath := filepath.Join(dir, "output.jsonl")

	oldJSONL := jsonLines
	jsonLines = true
	defer func() { jsonLines = oldJSONL }()

	jsonResultsMutex.Lock()
	jsonResults = nil
	jsonResultsMutex.Unlock()

	if err := initOutputWriter(outPath); err != nil {
		t.Fatalf("initOutputWriter: %v", err)
	}

	writeResultToOutput(Result{line: "GET /admin", statusCode: 200, contentLength: 1234, score: 88, likelihood: "high"}, "verb-tampering")
	writeResultToOutput(Result{line: "X-Original-URL: /", statusCode: 302, contentLength: 12, score: 67, likelihood: "medium"}, "header-confusion")
	closeOutputWriter()

	data, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatalf("read output: %v", err)
	}

	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	if len(lines) != 2 {
		t.Fatalf("expected 2 jsonl lines, got %d", len(lines))
	}

	var first JSONResult
	if err := json.Unmarshal([]byte(lines[0]), &first); err != nil {
		t.Fatalf("unmarshal first jsonl line: %v", err)
	}
	if first.Score != 88 || first.Likelihood != "high" {
		t.Fatalf("unexpected first jsonl result: %+v", first)
	}
}

func TestJSONLStreamsRecordsAsTheyArrive(t *testing.T) {
	// Arrange
	resetTestState()
	jsonOutput = false
	jsonLines = true
	defer func() { jsonLines = false }()

	path := filepath.Join(t.TempDir(), "findings.jsonl")
	if err := initOutputWriter(path); err != nil {
		t.Fatalf("initOutputWriter: %v", err)
	}
	defer closeOutputWriter()

	// Act: write one record, then read the file back before the run ends.
	writeResultToOutput(Result{line: "GET /admin", statusCode: 200, contentLength: 1234, score: 90, likelihood: "high"}, "verb-tampering")

	data, err := os.ReadFile(path) //nolint:gosec // test-controlled temp path
	if err != nil {
		t.Fatalf("read output: %v", err)
	}

	// Assert: the record is already on disk, not waiting for closeOutputWriter.
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	if len(lines) != 1 {
		t.Fatalf("expected 1 streamed line before close, got %d: %q", len(lines), string(data))
	}
	var record JSONResult
	if err := json.Unmarshal([]byte(lines[0]), &record); err != nil {
		t.Fatalf("streamed line is not valid JSON: %v (%q)", err, lines[0])
	}
	if record.Technique != "verb-tampering" || record.StatusCode != 200 {
		t.Errorf("unexpected streamed record: %+v", record)
	}
}

func TestJSONLRecordCarriesTheRequestThatProducedIt(t *testing.T) {
	// Arrange
	resetTestState()
	jsonOutput = false
	jsonLines = true
	defer func() { jsonLines = false }()

	path := filepath.Join(t.TempDir(), "findings.jsonl")
	if err := initOutputWriter(path); err != nil {
		t.Fatalf("initOutputWriter: %v", err)
	}

	// A url-override finding: the request goes to "/", not to the target /admin.
	result := Result{line: "X-Original-URL: /admin via /", statusCode: 200, contentLength: 3218, score: 100, likelihood: "high"}
	attachHTTPReplay(&result, "GET", "https://target.tld/", []header{{"X-Original-URL", "/admin"}}, "", false, nil, 5000)

	// Act
	writeResultToOutput(result, "url-override")
	closeOutputWriter()

	// Assert
	data, err := os.ReadFile(path) //nolint:gosec // test-controlled temp path
	if err != nil {
		t.Fatalf("read output: %v", err)
	}
	var record JSONResult
	if err := json.Unmarshal([]byte(strings.TrimSpace(string(data))), &record); err != nil {
		t.Fatalf("invalid JSONL: %v (%q)", err, string(data))
	}

	if record.Method != "GET" {
		t.Errorf("record.Method = %q, want GET", record.Method)
	}
	if record.URL != "https://target.tld/" {
		t.Errorf("record.URL = %q, want the URL actually requested (https://target.tld/)", record.URL)
	}
	if !strings.Contains(record.ReproCurl, "X-Original-URL: /admin") {
		t.Errorf("record.ReproCurl should carry the override header, got %q", record.ReproCurl)
	}
}

func TestJSONLBuffersWhenWritingToStdout(t *testing.T) {
	// Arrange: with no -o there is no separate sink, so records must be held
	// back rather than interleaved into the human-readable report on stdout.
	resetTestState()
	jsonOutput = false
	jsonLines = true
	defer func() { jsonLines = false }()
	outputWriter = nil

	// Act
	writeResultToOutput(Result{line: "GET /admin", statusCode: 200, contentLength: 10}, "verb-tampering")

	// Assert
	jsonResultsMutex.Lock()
	buffered := len(jsonResults)
	jsonResultsMutex.Unlock()
	if buffered != 1 {
		t.Fatalf("expected the record to be buffered for the stdout flush, got %d buffered", buffered)
	}
	if streamingJSONLines() {
		t.Error("streamingJSONLines() = true with no output file, want false")
	}
}
