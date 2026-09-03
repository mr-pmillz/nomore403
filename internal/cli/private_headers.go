package cli

import (
	"bytes"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"unicode/utf8"
)

const (
	privateHeaderMaxFileBytes  = 272 * 1024
	privateHeaderMaxEntries    = 16
	privateHeaderMaxNameBytes  = 256
	privateHeaderMaxValueBytes = 16 * 1024
	privateHeaderMaxCurlBytes  = 2*privateHeaderMaxFileBytes + 4096
)

var (
	errPrivateHeaderFileInvalid = errors.New("private header file is invalid")
	errPrivateHeaderConflict    = errors.New("private header conflicts with another request header")
	errPrivateHeaderOrigin      = errors.New("private header target origin is invalid")
	errPrivateHeaderRequest     = errors.New("request with private headers failed")
)

type privateHeader struct {
	name  string
	value []byte
}

// privateHeaderStore owns the only long-lived mutable copy of private values.
// It is loaded once per CLI run and wiped after all target work has joined.
type privateHeaderStore struct {
	entries []privateHeader
}

type requestOrigin struct {
	scheme string
	host   string
	port   string
}

// privateHeaders binds a loaded store to one explicit target origin. The
// pointer may be carried by an in-process replay, but is never serialized.
type privateHeaders struct {
	store  *privateHeaderStore
	origin requestOrigin
}

type privateRequestError struct {
	transient bool
}

func (e *privateRequestError) Error() string { return errPrivateHeaderRequest.Error() }
func (e *privateRequestError) Unwrap() error { return errPrivateHeaderRequest }

func privateRequestFailure(err error) error {
	return &privateRequestError{transient: errorLooksTransient(err)}
}

func loadPrivateHeaderFile(path string) (*privateHeaderStore, error) {
	file, err := openValidatedPrivateHeaderFile(path)
	if err != nil {
		return nil, errPrivateHeaderFileInvalid
	}
	defer func() { _ = file.Close() }()

	data, err := io.ReadAll(io.LimitReader(file, privateHeaderMaxFileBytes+1))
	if err != nil || len(data) > privateHeaderMaxFileBytes {
		wipeBytes(data)
		return nil, errPrivateHeaderFileInvalid
	}
	defer wipeBytes(data)

	return parsePrivateHeaderData(data)
}

func parsePrivateHeaderData(data []byte) (*privateHeaderStore, error) {
	if len(data) == 0 || len(data) > privateHeaderMaxFileBytes || bytes.IndexByte(data, 0) >= 0 || bytes.IndexByte(data, '\r') >= 0 {
		return nil, errPrivateHeaderFileInvalid
	}

	lines := bytes.Split(data, []byte{'\n'})
	if len(lines) > 0 && len(lines[len(lines)-1]) == 0 {
		lines = lines[:len(lines)-1]
	}
	if len(lines) == 0 || len(lines) > privateHeaderMaxEntries {
		return nil, errPrivateHeaderFileInvalid
	}

	store := &privateHeaderStore{entries: make([]privateHeader, 0, len(lines))}
	seen := make(map[string]struct{}, len(lines))
	fail := func() (*privateHeaderStore, error) {
		store.wipe()
		return nil, errPrivateHeaderFileInvalid
	}

	for _, line := range lines {
		if len(line) == 0 || !utf8.Valid(line) {
			return fail()
		}
		colon := bytes.IndexByte(line, ':')
		if colon <= 0 || colon+1 >= len(line) || line[colon+1] != ' ' {
			return fail()
		}

		nameBytes := line[:colon]
		valueBytes := line[colon+2:]
		if len(nameBytes) > privateHeaderMaxNameBytes || !validHeaderToken(nameBytes) ||
			len(valueBytes) == 0 || len(valueBytes) > privateHeaderMaxValueBytes ||
			!utf8.Valid(valueBytes) || !validHeaderValue(valueBytes) {
			return fail()
		}

		name := string(nameBytes)
		canonical := strings.ToLower(name)
		if _, exists := seen[canonical]; exists {
			return fail()
		}
		seen[canonical] = struct{}{}

		value := make([]byte, len(valueBytes))
		copy(value, valueBytes)
		store.entries = append(store.entries, privateHeader{name: name, value: value})
	}

	return store, nil
}

func validHeaderValue(value []byte) bool {
	for _, c := range value {
		if (c < 0x20 && c != '\t') || c == 0x7f {
			return false
		}
	}
	return true
}

func validHeaderToken(name []byte) bool {
	if len(name) == 0 {
		return false
	}
	for _, c := range name {
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') {
			continue
		}
		switch c {
		case '!', '#', '$', '%', '&', '\'', '*', '+', '-', '.', '^', '_', '`', '|', '~':
			continue
		default:
			return false
		}
	}
	return true
}

func (s *privateHeaderStore) wipe() {
	if s == nil {
		return
	}
	for i := range s.entries {
		wipeBytes(s.entries[i].value)
		s.entries[i].value = nil
		s.entries[i].name = ""
	}
	s.entries = nil
}

func wipeBytes(data []byte) {
	for i := range data {
		data[i] = 0
	}
}

func (s *privateHeaderStore) forTarget(target string) (*privateHeaders, error) {
	if s == nil {
		return nil, nil
	}
	origin, err := normalizeOrigin(target)
	if err != nil {
		return nil, errPrivateHeaderOrigin
	}
	return &privateHeaders{store: s, origin: origin}, nil
}

func normalizeOrigin(rawURL string) (requestOrigin, error) {
	parsed, err := url.Parse(rawURL)
	if err != nil || parsed == nil || parsed.User != nil || parsed.Hostname() == "" {
		return requestOrigin{}, errPrivateHeaderOrigin
	}
	scheme := strings.ToLower(parsed.Scheme)
	if scheme != "http" && scheme != "https" {
		return requestOrigin{}, errPrivateHeaderOrigin
	}
	port := parsed.Port()
	if port == "" {
		if scheme == "http" {
			port = "80"
		} else {
			port = "443"
		}
	} else {
		number, err := strconv.Atoi(port)
		if err != nil || number < 1 || number > 65535 {
			return requestOrigin{}, errPrivateHeaderOrigin
		}
		port = strconv.Itoa(number)
	}
	return requestOrigin{scheme: scheme, host: strings.ToLower(parsed.Hostname()), port: port}, nil
}

func (p *privateHeaders) appliesTo(rawURL string) bool {
	if p == nil || p.store == nil {
		return false
	}
	origin, err := normalizeOrigin(rawURL)
	return err == nil && origin == p.origin
}

func (p *privateHeaders) validatePublic(headers []header) error {
	if p == nil || p.store == nil {
		return nil
	}
	for _, private := range p.store.entries {
		switch strings.ToLower(private.name) {
		case "host", "content-length", "transfer-encoding", "connection", "trailer", "upgrade", "proxy-connection":
			return errPrivateHeaderConflict
		}
		for _, public := range headers {
			if strings.EqualFold(public.key, private.name) {
				return errPrivateHeaderConflict
			}
		}
	}
	return nil
}

func (p *privateHeaders) applyHTTPHeaders(headers http.Header, rawURL string) {
	if p == nil || p.store == nil {
		return
	}
	// Always remove protected names first. Redirected requests can inherit the
	// original header map; only an exact origin match is allowed to add them.
	for _, private := range p.store.entries {
		headers.Del(private.name)
	}
	if !p.appliesTo(rawURL) {
		return
	}
	for _, private := range p.store.entries {
		headers.Add(private.name, string(private.value))
	}
}

func (p *privateHeaders) containsPrivateData(value string) bool {
	if p == nil || p.store == nil || value == "" {
		return false
	}
	for _, private := range p.store.entries {
		if strings.Contains(strings.ToLower(value), strings.ToLower(private.name)) ||
			strings.Contains(value, string(private.value)) {
			return true
		}
	}
	return false
}

func (p *privateHeaders) redactResponseInfo(resp *ResponseInfo) {
	if resp == nil {
		return
	}
	for _, value := range []*string{&resp.location, &resp.contentType, &resp.server, &resp.via, &resp.xCache, &resp.poweredBy, &resp.cfRay} {
		if p.containsPrivateData(*value) {
			*value = ""
		}
	}
}

func (p *privateHeaders) redactResult(result *Result) {
	if result == nil {
		return
	}
	for _, value := range []*string{&result.location, &result.contentType, &result.server} {
		if p.containsPrivateData(*value) {
			*value = ""
		}
	}
}

type privateOriginTransport struct {
	base    http.RoundTripper
	private *privateHeaders
}

func (t privateOriginTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	clone := req.Clone(req.Context())
	clone.Header = req.Header.Clone()
	t.private.applyHTTPHeaders(clone.Header, clone.URL.String())
	return t.base.RoundTrip(clone)
}

func (p *privateHeaders) curlConfig(rawURL string) ([]byte, error) {
	if p == nil || p.store == nil || !p.appliesTo(rawURL) {
		return nil, nil
	}
	var config bytes.Buffer
	for _, private := range p.store.entries {
		config.WriteString("header = \"")
		writeCurlConfigEscaped(&config, []byte(private.name))
		config.WriteString(": ")
		writeCurlConfigEscaped(&config, private.value)
		config.WriteString("\"\n")
		if config.Len() > privateHeaderMaxCurlBytes {
			data := config.Bytes()
			wipeBytes(data)
			return nil, errPrivateHeaderFileInvalid
		}
	}
	data := make([]byte, config.Len())
	copy(data, config.Bytes())
	wipeBytes(config.Bytes())
	return data, nil
}

func writeCurlConfigEscaped(dst *bytes.Buffer, value []byte) {
	for _, c := range value {
		switch c {
		case '\\', '"':
			dst.WriteByte('\\')
			dst.WriteByte(c)
		case '\t':
			dst.WriteString(`\t`)
		default:
			dst.WriteByte(c)
		}
	}
}

func requestURLFromCurlArgs(args []string) string {
	for i := len(args) - 1; i >= 0; i-- {
		candidate := args[i]
		if strings.HasPrefix(candidate, "http://") || strings.HasPrefix(candidate, "https://") {
			return candidate
		}
	}
	return ""
}

func curlArgumentHeaders(args []string) []header {
	var headers []header
	for i := 0; i+1 < len(args); i++ {
		if args[i] != "-H" && args[i] != "--header" {
			continue
		}
		name, _, ok := strings.Cut(args[i+1], ":")
		if ok {
			headers = append(headers, header{key: name})
		}
		i++
	}
	return headers
}

func privateRawHeaderBytes(p *privateHeaders, rawURL string) []byte {
	if p == nil || p.store == nil || !p.appliesTo(rawURL) {
		return nil
	}
	var data bytes.Buffer
	for _, private := range p.store.entries {
		data.WriteString(private.name)
		data.WriteString(": ")
		data.Write(private.value)
		data.WriteString("\r\n")
	}
	result := make([]byte, data.Len())
	copy(result, data.Bytes())
	wipeBytes(data.Bytes())
	return result
}
