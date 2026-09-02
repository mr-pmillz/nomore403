package cli

import (
	"encoding/json"
	"fmt"
	"os"
	"sync"
)

// JSONResult represents a single result in JSON output format.
type JSONResult struct {
	StatusCode    int    `json:"status_code"`
	ContentLength int    `json:"content_length"`
	Technique     string `json:"technique"`
	Payload       string `json:"payload"`
	Score         int    `json:"score"`
	Likelihood    string `json:"likelihood"`
	ScoreReason   string `json:"score_reason,omitempty"`
	Method        string `json:"method,omitempty"`
	URL           string `json:"url,omitempty"`
	RequestTarget string `json:"request_target,omitempty"`
	BodyHash      string `json:"body_hash,omitempty"`
	Location      string `json:"location,omitempty"`
	ContentType   string `json:"content_type,omitempty"`
	Server        string `json:"server,omitempty"`
	ReproCurl     string `json:"repro_curl,omitempty"`
}

var (
	outputWriter *os.File
	// jsonResults buffers records for --json, which has to be one array
	// document and therefore cannot be written until the run ends. --jsonl
	// streams instead and never touches this.
	jsonResults      []JSONResult
	jsonResultsMutex sync.Mutex
)

// streamingJSONLines reports whether records should be written one per line as
// they are found rather than buffered to the end of the run. Streaming needs a
// destination of its own: with -o the file is that destination, while without
// it the only sink is stdout, which the human-readable report is already using.
func streamingJSONLines() bool {
	return jsonLines && outputWriter != nil
}

// initOutputWriter opens the output file for writing.
func initOutputWriter(path string) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	outputWriter = f
	return nil
}

// closeOutputWriter flushes and closes the output file.
// If JSON mode is enabled, writes the accumulated JSON results.
func closeOutputWriter() {
	if outputWriter == nil {
		return
	}

	// --jsonl already wrote every record as it was found; only the single-document
	// --json form still owes the file its contents.
	if jsonOutput && !jsonLines {
		jsonResultsMutex.Lock()
		data, err := json.MarshalIndent(jsonResults, "", "  ")
		jsonResultsMutex.Unlock()
		if err != nil {
			fmt.Fprintf(os.Stderr, "[!] Error marshaling JSON: %v\n", err)
		} else {
			data = append(data, '\n')
			if _, writeErr := outputWriter.Write(data); writeErr != nil {
				fmt.Fprintf(os.Stderr, "[!] Error writing JSON output: %v\n", writeErr)
			}
		}
	}

	if err := outputWriter.Close(); err != nil {
		fmt.Fprintf(os.Stderr, "[!] Error closing output file: %v\n", err)
	}
	outputWriter = nil
}

// writeJSONLine marshals one record and appends it to the output file as a
// single line. Caller MUST hold jsonResultsMutex.
func writeJSONLineLocked(record JSONResult) {
	data, err := json.Marshal(record)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[!] Error marshaling JSON: %v\n", err)
		return
	}
	data = append(data, '\n')
	if _, err := outputWriter.Write(data); err != nil {
		fmt.Fprintf(os.Stderr, "[!] Error writing JSONL output: %v\n", err)
	}
}

// jsonRecord converts a result into its serialisable form. The replay spec
// carries the request that actually produced the response, which is not always
// the target URL -- url-override, for one, reports findings for requests aimed
// at a different path entirely.
func jsonRecord(result Result, technique string) JSONResult {
	record := JSONResult{
		StatusCode:    result.statusCode,
		ContentLength: result.contentLength,
		Technique:     technique,
		Payload:       result.line,
		Score:         result.score,
		Likelihood:    result.likelihood,
		ScoreReason:   result.scoreReason,
		BodyHash:      result.bodyHash,
		Location:      result.location,
		ContentType:   result.contentType,
		Server:        result.server,
		ReproCurl:     result.reproCurl,
	}
	if result.replay != nil {
		record.Method = result.replay.method
		record.URL = result.replay.uri
		record.RequestTarget = result.replay.requestTarget
	}
	return record
}

// writeResultToOutput writes a result to the output file.
// With --jsonl and -o it streams one JSON object per line as results arrive;
// with --json, or when writing to stdout, it accumulates them for the flush at
// the end of the run (thread-safe via jsonResultsMutex).
// In plain mode, it writes immediately — caller MUST hold printMutex.
func writeResultToOutput(result Result, technique string) {
	if outputWriter == nil && !jsonOutput && !jsonLines {
		return
	}

	if jsonOutput || jsonLines {
		record := jsonRecord(result, technique)

		jsonResultsMutex.Lock()
		defer jsonResultsMutex.Unlock()

		if streamingJSONLines() {
			// One record per line, flushed as it is found, so the file can be
			// tailed or fed to a consumer while the scan is still running.
			writeJSONLineLocked(record)
			return
		}
		// Buffered: --json needs a whole array, and a stdout run has to wait
		// until the human-readable report is done before emitting anything.
		jsonResults = append(jsonResults, record)
		return
	}

	if outputWriter != nil {
		fmt.Fprintf(outputWriter, "%d\t[%d %s]\t%d bytes\t%s\n", result.statusCode, result.score, result.likelihood, result.contentLength, result.line)
		if result.reproCurl != "" {
			fmt.Fprintf(outputWriter, "curl\t%s\n", result.reproCurl)
		}
	}
}

// flushJSONToStdout writes JSON results to stdout when no output file is specified.
func flushJSONToStdout() {
	if (!jsonOutput && !jsonLines) || outputWriter != nil {
		return
	}

	jsonResultsMutex.Lock()
	defer jsonResultsMutex.Unlock()

	if len(jsonResults) == 0 {
		return
	}

	if jsonLines {
		for _, item := range jsonResults {
			data, err := json.Marshal(item)
			if err != nil {
				fmt.Fprintf(os.Stderr, "[!] Error marshaling JSON: %v\n", err)
				return
			}
			fmt.Println(string(data))
		}
		return
	}
	data, err := json.MarshalIndent(jsonResults, "", "  ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "[!] Error marshaling JSON: %v\n", err)
		return
	}
	fmt.Println(string(data))
}
