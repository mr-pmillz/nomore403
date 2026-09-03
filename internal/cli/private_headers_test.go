package cli

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"unicode/utf8"
)

const privateSentinel = "n403-private-9f7d6c31e28a4b50"

func writePrivateHeaderFile(t *testing.T, contents []byte, mode os.FileMode) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "credential.conf")
	if err := os.WriteFile(path, contents, mode); err != nil {
		t.Fatalf("write private header file: %v", err)
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatalf("chmod private header file: %v", err)
	}
	return path
}

func TestParsePrivateHeaderDataAcceptsOneAndSixteenEntries(t *testing.T) {
	t.Run("one preserves colons and spaces", func(t *testing.T) {
		store, err := parsePrivateHeaderData([]byte("Authorization: Bearer  value:with:colons  \n"))
		if err != nil {
			t.Fatalf("parse: %v", err)
		}
		defer store.wipe()
		if got, want := len(store.entries), 1; got != want {
			t.Fatalf("entry count: got %d want %d", got, want)
		}
		if got, want := store.entries[0].name, "Authorization"; got != want {
			t.Fatalf("name: got %q want %q", got, want)
		}
		if got, want := string(store.entries[0].value), "Bearer  value:with:colons  "; got != want {
			t.Fatalf("value: got %q want %q", got, want)
		}
	})

	t.Run("sixteen", func(t *testing.T) {
		var input strings.Builder
		for i := 0; i < privateHeaderMaxEntries; i++ {
			fmt.Fprintf(&input, "X-Private-%02d: value-%02d\n", i, i)
		}
		store, err := parsePrivateHeaderData([]byte(input.String()))
		if err != nil {
			t.Fatalf("parse: %v", err)
		}
		defer store.wipe()
		if got := len(store.entries); got != privateHeaderMaxEntries {
			t.Fatalf("entry count: got %d", got)
		}
	})
}

func TestParsePrivateHeaderDataRejectsInvalidInputWithoutDisclosure(t *testing.T) {
	oversizedValue := strings.Repeat("v", privateHeaderMaxValueBytes+1)
	oversizedName := strings.Repeat("N", privateHeaderMaxNameBytes+1)
	invalidUTF8 := append([]byte("X-Test: "), 0xff)
	tests := map[string][]byte{
		"empty file":      {},
		"blank line":      []byte("X-One: value\n\nX-Two: value\n"),
		"comment":         []byte("# private\n"),
		"missing colon":   []byte("X-Test value\n"),
		"missing space":   []byte("X-Test:value\n"),
		"invalid name":    []byte("X Test: value\n"),
		"duplicate case":  []byte("X-Test: one\nx-test: two\n"),
		"empty value":     []byte("X-Test: \n"),
		"oversized value": []byte("X-Test: " + oversizedValue + "\n"),
		"oversized name":  []byte(oversizedName + ": value\n"),
		"invalid UTF-8":   invalidUTF8,
		"NUL":             []byte("X-Test: before\x00after\n"),
		"CRLF":            []byte("X-Test: value\r\n"),
	}
	var tooMany strings.Builder
	for i := 0; i <= privateHeaderMaxEntries; i++ {
		fmt.Fprintf(&tooMany, "X-Test-%d: value\n", i)
	}
	tests["too many entries"] = []byte(tooMany.String())

	for name, input := range tests {
		t.Run(name, func(t *testing.T) {
			store, err := parsePrivateHeaderData(input)
			if store != nil {
				store.wipe()
			}
			if !errors.Is(err, errPrivateHeaderFileInvalid) {
				t.Fatalf("error: got %v want stable private-file error", err)
			}
			if strings.Contains(fmt.Sprint(err), "X-Test") || strings.Contains(fmt.Sprint(err), privateSentinel) {
				t.Fatalf("error disclosed private input: %v", err)
			}
		})
	}
}

func TestLoadPrivateHeaderFileSecurityAndSize(t *testing.T) {
	t.Run("valid owner-only regular file", func(t *testing.T) {
		path := writePrivateHeaderFile(t, []byte("Authorization: "+privateSentinel+"\n"), 0o600)
		store, err := loadPrivateHeaderFile(path)
		if err != nil {
			t.Fatalf("load: %v", err)
		}
		defer store.wipe()
	})

	t.Run("permissive mode", func(t *testing.T) {
		path := writePrivateHeaderFile(t, []byte("X-Test: value\n"), 0o644)
		_, err := loadPrivateHeaderFile(path)
		if !errors.Is(err, errPrivateHeaderFileInvalid) {
			t.Fatalf("error: got %v", err)
		}
	})

	t.Run("non regular", func(t *testing.T) {
		_, err := loadPrivateHeaderFile(t.TempDir())
		if !errors.Is(err, errPrivateHeaderFileInvalid) {
			t.Fatalf("error: got %v", err)
		}
	})

	t.Run("oversized file", func(t *testing.T) {
		path := writePrivateHeaderFile(t, bytes.Repeat([]byte{'x'}, privateHeaderMaxFileBytes+1), 0o600)
		_, err := loadPrivateHeaderFile(path)
		if !errors.Is(err, errPrivateHeaderFileInvalid) {
			t.Fatalf("error: got %v", err)
		}
	})

	if runtime.GOOS != "windows" {
		t.Run("symlink", func(t *testing.T) {
			target := writePrivateHeaderFile(t, []byte("X-Test: value\n"), 0o600)
			link := filepath.Join(t.TempDir(), "credential-link")
			if err := os.Symlink(target, link); err != nil {
				t.Fatalf("symlink: %v", err)
			}
			_, err := loadPrivateHeaderFile(link)
			if !errors.Is(err, errPrivateHeaderFileInvalid) {
				t.Fatalf("error: got %v", err)
			}
		})
	}

	if os.Geteuid() == 0 {
		t.Run("wrong owner", func(t *testing.T) {
			path := writePrivateHeaderFile(t, []byte("X-Test: value\n"), 0o600)
			if err := os.Chown(path, 65534, 65534); err != nil {
				t.Skipf("cannot change owner: %v", err)
			}
			_, err := loadPrivateHeaderFile(path)
			if !errors.Is(err, errPrivateHeaderFileInvalid) {
				t.Fatalf("error: got %v", err)
			}
		})
	}
}

func TestPrivateHeadersRejectPublicAndGeneratedCollisions(t *testing.T) {
	store, err := parsePrivateHeaderData([]byte("X-API-Key: " + privateSentinel + "\n"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.wipe()
	private, err := store.forTarget("https://example.com/admin")
	if err != nil {
		t.Fatal(err)
	}

	for _, public := range [][]header{
		{{key: "x-api-key", value: "public"}},
		{{key: "X-API-KEY", value: "generated"}},
	} {
		err := private.validatePublic(public)
		if !errors.Is(err, errPrivateHeaderConflict) {
			t.Fatalf("expected collision for %#v", public)
		}
		if strings.Contains(err.Error(), "X-API-Key") || strings.Contains(err.Error(), privateSentinel) {
			t.Fatalf("collision error disclosed private data: %v", err)
		}
	}

	uaStore, err := parsePrivateHeaderData([]byte("User-Agent: " + privateSentinel + "\n"))
	if err != nil {
		t.Fatal(err)
	}
	defer uaStore.wipe()
	uaPrivate, err := uaStore.forTarget("https://example.com")
	if err != nil {
		t.Fatal(err)
	}
	if !errors.Is(uaPrivate.validatePublic([]header{{key: "User-Agent", value: "nomore403"}}), errPrivateHeaderConflict) {
		t.Fatal("expected User-Agent collision")
	}
}

func TestPrivateHeadersAreOriginScopedAcrossHTTPRedirects(t *testing.T) {
	var crossOriginSeen atomic.Bool
	crossOrigin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		crossOriginSeen.Store(r.Header.Get("Authorization") != "")
		w.WriteHeader(http.StatusOK)
	}))
	defer crossOrigin.Close()

	var initialSeen atomic.Bool
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") == privateSentinel {
			initialSeen.Store(true)
		}
		http.Redirect(w, r, crossOrigin.URL+"/landing", http.StatusFound)
	}))
	defer origin.Close()

	store, err := parsePrivateHeaderData([]byte("Authorization: " + privateSentinel + "\n"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.wipe()
	private, err := store.forTarget(origin.URL + "/admin")
	if err != nil {
		t.Fatal(err)
	}

	if _, err := requestWithRetryPrivate("GET", origin.URL+"/admin", nil, nil, false, 2000, true, private); err != nil {
		t.Fatalf("request: %v", err)
	}
	if !initialSeen.Load() {
		t.Fatal("private header was not delivered to the explicit origin")
	}
	if crossOriginSeen.Load() {
		t.Fatal("private header crossed an origin redirect")
	}
}

func TestNormalizeOriginUsesEffectivePort(t *testing.T) {
	implicit, err := normalizeOrigin("HTTP://EXAMPLE.COM/path")
	if err != nil {
		t.Fatal(err)
	}
	explicit, err := normalizeOrigin("http://example.com:080/other")
	if err != nil {
		t.Fatal(err)
	}
	if implicit != explicit {
		t.Fatalf("effective origins differ: %#v != %#v", implicit, explicit)
	}
	if _, err := normalizeOrigin("http://example.com:65536"); !errors.Is(err, errPrivateHeaderOrigin) {
		t.Fatalf("expected invalid port rejection, got %v", err)
	}
}

func TestPrivateHeadersRemainOnSameOriginRedirect(t *testing.T) {
	var redirectedSeen atomic.Bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/start" {
			http.Redirect(w, r, "/end", http.StatusFound)
			return
		}
		redirectedSeen.Store(r.Header.Get("X-API-Key") == privateSentinel)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	store, _ := parsePrivateHeaderData([]byte("X-API-Key: " + privateSentinel + "\n"))
	defer store.wipe()
	private, _ := store.forTarget(server.URL + "/start")
	if _, err := requestWithRetryPrivate("GET", server.URL+"/start", nil, nil, false, 2000, true, private); err != nil {
		t.Fatal(err)
	}
	if !redirectedSeen.Load() {
		t.Fatal("private header was stripped from a same-origin redirect")
	}
}

func TestPrivateHeadersAreAppliedToRetriesAndCalibration(t *testing.T) {
	oldRetryCount, oldBackoff := retryCount, retryBackoffMs
	retryCount, retryBackoffMs = 1, 1
	defer func() {
		retryCount, retryBackoffMs = oldRetryCount, oldBackoff
	}()

	var requests atomic.Int32
	var missing atomic.Bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempt := requests.Add(1)
		if r.Header.Get("Authorization") != privateSentinel {
			missing.Store(true)
		}
		if r.URL.Path == "/retry" && attempt == 1 {
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	store, _ := parsePrivateHeaderData([]byte("Authorization: " + privateSentinel + "\n"))
	defer store.wipe()
	private, _ := store.forTarget(server.URL + "/retry")
	if _, err := requestWithRetryPrivate("GET", server.URL+"/retry", nil, nil, false, 2000, false, private); err != nil {
		t.Fatalf("retry request: %v", err)
	}

	options := RequestOptions{
		uri:            server.URL + "/admin",
		method:         "GET",
		proxy:          &url.URL{},
		timeout:        2000,
		privateHeaders: private,
	}
	runAutocalibrate(options)
	if missing.Load() {
		t.Fatal("private header was absent from a retry or calibration request")
	}
	if got := requests.Load(); got < 5 {
		t.Fatalf("expected retry and calibration requests, got %d", got)
	}
}

func TestGeneratedPrivateHeaderCollisionMakesNoRequest(t *testing.T) {
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()
	store, _ := parsePrivateHeaderData([]byte("X-Generated: " + privateSentinel + "\n"))
	defer store.wipe()
	private, _ := store.forTarget(server.URL)

	_, err := requestWithRetryPrivate("GET", server.URL, []header{{key: "x-generated", value: "payload"}}, nil, false, 2000, false, private)
	if !errors.Is(err, errPrivateHeaderConflict) {
		t.Fatalf("error: got %v", err)
	}
	if got := requests.Load(); got != 0 {
		t.Fatalf("requests after generated collision: %d", got)
	}
}

func TestTechniqueGeneratedCollisionFailsPreflight(t *testing.T) {
	store, _ := parsePrivateHeaderData([]byte("X-HTTP-Method-Override: " + privateSentinel + "\n"))
	defer store.wipe()
	private, _ := store.forTarget("https://example.com/admin")
	options := RequestOptions{privateHeaders: private, techniques: []string{"method-override"}}
	if err := validatePrivateTechniqueCollisions(options); !errors.Is(err, errPrivateHeaderConflict) {
		t.Fatalf("error: got %v", err)
	}
}

func TestPrivateResponseReflectionsAreRedacted(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Location", "/reflected/"+privateSentinel)
		w.Header().Set("Server", "Authorization")
		w.WriteHeader(http.StatusFound)
	}))
	defer server.Close()
	store, _ := parsePrivateHeaderData([]byte("Authorization: " + privateSentinel + "\n"))
	defer store.wipe()
	private, _ := store.forTarget(server.URL)

	resp, err := requestWithRetryPrivate("GET", server.URL, nil, nil, false, 2000, false, private)
	if err != nil {
		t.Fatal(err)
	}
	if resp.location != "" || resp.server != "" {
		t.Fatalf("reflected private data was retained: %#v", resp)
	}
}

func TestPrivateHeadersReachRawRequestWithoutReplayDisclosure(t *testing.T) {
	seen := make(chan string, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen <- r.Header.Get("Authorization")
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	store, _ := parsePrivateHeaderData([]byte("Authorization: " + privateSentinel + "\n"))
	defer store.wipe()
	private, _ := store.forTarget(server.URL + "/raw")
	if _, err := rawRequestPrivate("GET", server.URL+"/raw", "/raw", nil, "", 2000, private); err != nil {
		t.Fatalf("raw request: %v", err)
	}
	if got := <-seen; got != privateSentinel {
		t.Fatalf("raw private header: got %q", got)
	}

	result := Result{}
	attachRawReplay(&result, "GET", server.URL+"/raw", "/raw", nil, "", 2000, private)
	encoded, err := json.Marshal(jsonRecord(result, "raw-authority"))
	if err != nil {
		t.Fatal(err)
	}
	for _, leaked := range []string{"Authorization", privateSentinel} {
		if strings.Contains(result.reproCurl, leaked) || strings.Contains(string(encoded), leaked) {
			t.Fatalf("private data leaked through raw replay/output: %q", leaked)
		}
	}
}

func TestCurlPrivateHeadersUseStdinAndNeverArgvEnvOrReplay(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("test helper uses a POSIX shell")
	}
	tmp := t.TempDir()
	argsPath := filepath.Join(tmp, "args")
	envPath := filepath.Join(tmp, "env")
	stdinPath := filepath.Join(tmp, "stdin")
	script := filepath.Join(tmp, "curl")
	scriptBody := "#!/bin/sh\nprintf '%s\\n' \"$@\" > \"$N403_ARGS\"\nenv > \"$N403_ENV\"\ncat > \"$N403_STDIN\"\nprintf 'HTTP/1.1 200 OK\\r\\nContent-Length: 0\\r\\n\\r\\n'\n"
	if err := os.WriteFile(script, []byte(scriptBody), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", tmp+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("N403_ARGS", argsPath)
	t.Setenv("N403_ENV", envPath)
	t.Setenv("N403_STDIN", stdinPath)

	store, _ := parsePrivateHeaderData([]byte("X-Private-Key: " + privateSentinel + "\n"))
	defer store.wipe()
	private, _ := store.forTarget("https://example.com/admin")
	args := []string{"-i", "-s", "-L", "--insecure", "https://example.com/admin"}
	result := curlRequestPrivate(args, "--http1.1", 2000, private)
	if result.statusCode != http.StatusOK {
		t.Fatalf("curl status: got %d", result.statusCode)
	}

	argv, _ := os.ReadFile(argsPath)
	environ, _ := os.ReadFile(envPath)
	stdin, _ := os.ReadFile(stdinPath)
	if !strings.Contains(string(argv), "--config\n-\n") {
		t.Fatalf("curl argv lacks fixed stdin config flags: %q", argv)
	}
	if bytes.Contains(argv, []byte("-L\n")) {
		t.Fatalf("curl redirect following remained enabled with private headers: %q", argv)
	}
	for label, data := range map[string][]byte{"argv": argv, "env": environ} {
		if bytes.Contains(data, []byte("X-Private-Key")) || bytes.Contains(data, []byte(privateSentinel)) {
			t.Fatalf("private data leaked through curl %s", label)
		}
	}
	if !bytes.Contains(stdin, []byte("X-Private-Key: "+privateSentinel)) || len(stdin) > privateHeaderMaxCurlBytes {
		t.Fatalf("unexpected curl stdin config: %q", stdin)
	}

	attachCurlReplay(&result, args, "curl public-only", 2000, private)
	if strings.Contains(strings.Join(result.replay.curlArgs, " "), privateSentinel) ||
		strings.Contains(result.reproCurl, privateSentinel) || strings.Contains(result.reproCurl, "X-Private-Key") {
		t.Fatal("private data leaked into curl replay state")
	}
}

func TestCurlGeneratedHeaderCollisionIsRejectedBeforeExecution(t *testing.T) {
	store, _ := parsePrivateHeaderData([]byte("Accept: " + privateSentinel + "\n"))
	defer store.wipe()
	private, _ := store.forTarget("https://example.com")
	_, _, err := prepareCurlInvocation([]string{"-H", "Accept:", "https://example.com"}, private)
	if !errors.Is(err, errPrivateHeaderConflict) {
		t.Fatalf("error: got %v", err)
	}
}

func TestPrivateHeadersStayOutOfBannerResultReplayAndJSON(t *testing.T) {
	store, _ := parsePrivateHeaderData([]byte("X-Private-Key: " + privateSentinel + "\n"))
	defer store.wipe()
	private, _ := store.forTarget("https://example.com/admin")
	options := RequestOptions{
		uri:            "https://example.com/admin",
		method:         "GET",
		proxy:          &url.URL{},
		userAgent:      "nomore403",
		headers:        []header{{key: "User-Agent", value: "nomore403"}},
		techniques:     []string{"headers"},
		privateHeaders: private,
	}

	read, write, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	oldStdout := os.Stdout
	os.Stdout = write
	showVerboseBanner(options)
	_ = write.Close()
	os.Stdout = oldStdout
	banner, err := io.ReadAll(read)
	if err != nil {
		t.Fatal(err)
	}
	_ = read.Close()

	result := Result{line: "public payload", statusCode: http.StatusOK}
	attachHTTPReplay(&result, "GET", options.uri, options.headers, "", false, nil, 2000, private)
	record := jsonRecord(result, "headers")
	encoded, err := json.Marshal(record)
	if err != nil {
		t.Fatal(err)
	}
	publicReplay := result.reproCurl + strings.Join(result.replay.curlArgs, " ")
	for _, data := range []string{string(banner), string(encoded), result.line, publicReplay} {
		if strings.Contains(data, "X-Private-Key") || strings.Contains(data, privateSentinel) {
			t.Fatalf("private data leaked into output state: %q", data)
		}
	}
	if result.replay.private != private {
		t.Fatal("same-process replay lost its non-serializable private reference")
	}

	resetMaps()
	recordFinding(result)
	clearPrivateReplayReferences()
	if topFindings[0].replay.private != nil {
		t.Fatal("target cleanup retained the private replay reference")
	}
}

func TestHeaderFileFlagIsDocumentedWithoutEnvironmentAlternative(t *testing.T) {
	flag := rootCmd.PersistentFlags().Lookup("header-file")
	if flag == nil {
		t.Fatal("--header-file flag is not registered")
	}
	usage := strings.ToLower(flag.Usage)
	if !strings.Contains(usage, "owner-only") || strings.Contains(usage, "env") {
		t.Fatalf("unexpected --header-file help: %q", flag.Usage)
	}
}

func TestPrivateValueMustBeValidUTF8Bytes(t *testing.T) {
	value := strings.Repeat("界", privateHeaderMaxValueBytes/3)
	if !utf8.ValidString(value) {
		t.Fatal("test input is invalid")
	}
	store, err := parsePrivateHeaderData([]byte("X-Test: " + value + "\n"))
	if err != nil {
		t.Fatalf("parse max UTF-8 value: %v", err)
	}
	store.wipe()

	_, err = parsePrivateHeaderData([]byte("X-Test: " + value + "界\n"))
	if !errors.Is(err, errPrivateHeaderFileInvalid) {
		t.Fatalf("expected byte-size rejection, got %v", err)
	}
}

func TestPrivateHeaderValidationFailureMakesNoRequest(t *testing.T) {
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	path := writePrivateHeaderFile(t, []byte("Authorization: "+privateSentinel+"\n"), 0o644)
	if store, err := loadPrivateHeaderFile(path); err == nil {
		store.wipe()
		t.Fatal("expected validation failure")
	}
	if got := requests.Load(); got != 0 {
		t.Fatalf("outbound requests after validation failure: %d", got)
	}
}
