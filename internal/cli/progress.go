package cli

import (
	"fmt"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/term"
)

// progressMode selects how per-technique progress is reported.
type progressMode int32

const (
	// progressOff reports nothing at all.
	progressOff progressMode = iota
	// progressTTY redraws an animated bar in place using ANSI escapes. Only
	// meaningful when stderr is a terminal.
	progressTTY
	// progressPlain writes append-only status lines with no escape codes and no
	// carriage returns, so progress survives being piped, redirected to a file,
	// or captured by a CI log.
	progressPlain
)

// progressPreference is the --progress flag value; see resolveProgressMode.
var progressPreference = progressPreferenceAuto

const (
	progressPreferenceAuto  = "auto"
	progressPreferenceTTY   = "tty"
	progressPreferencePlain = "plain"
	progressPreferenceNone  = "none"
)

// progressPreferences lists the accepted --progress values, for validation and
// for the flag's help text.
var progressPreferences = []string{
	progressPreferenceAuto,
	progressPreferenceTTY,
	progressPreferencePlain,
	progressPreferenceNone,
}

// plainMilestoneMin is the smallest technique size worth emitting intermediate
// percentage lines for. Below it the start and done lines carry enough signal
// and extra lines would just be log noise.
const plainMilestoneMin = 20

// plainMilestones are the completion percentages reported in plain mode.
var plainMilestones = []int{25, 50, 75}

// atomicProgressMode caches the resolved mode; -1 means "not resolved yet".
var atomicProgressMode int32 = -1

// validateProgressPreference reports whether v is an accepted --progress value.
func validateProgressPreference(v string) error {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case progressPreferenceAuto, progressPreferenceTTY, progressPreferencePlain, progressPreferenceNone:
		return nil
	default:
		return fmt.Errorf("invalid --progress value %q (want one of: %s)", v, strings.Join(progressPreferences, ", "))
	}
}

// resolveProgressMode maps a --progress preference onto a mode. "auto" reports
// a live bar only when stderr is a terminal, and falls back to plain status
// lines everywhere else, so a redirected or piped run still shows liveness
// instead of going silent.
func resolveProgressMode(preference string) progressMode {
	switch strings.ToLower(strings.TrimSpace(preference)) {
	case progressPreferenceNone:
		return progressOff
	case progressPreferenceTTY:
		return progressTTY
	case progressPreferencePlain:
		return progressPlain
	default:
		if isStderrTerminal() {
			return progressTTY
		}
		return progressPlain
	}
}

// isStderrTerminal reports whether progress can be drawn in place.
func isStderrTerminal() bool {
	return term.IsTerminal(int(os.Stderr.Fd()))
}

// currentProgressMode returns the resolved mode, resolving it on first use.
func currentProgressMode() progressMode {
	if m := atomic.LoadInt32(&atomicProgressMode); m >= 0 {
		return progressMode(m)
	}
	m := resolveProgressMode(progressPreference)
	atomic.StoreInt32(&atomicProgressMode, int32(m))
	return m
}

// setProgressMode pins the reporting mode, bypassing detection.
func setProgressMode(m progressMode) { atomic.StoreInt32(&atomicProgressMode, int32(m)) }

// activeProgress is the currently displayed progress bar, if any. It is only
// ever set in progressTTY mode, since it exists to be erased and redrawn around
// result output. Protected by printMutex.
var activeProgress *progress

// clearActiveProgress erases the active progress bar from the terminal.
// Caller MUST hold printMutex.
func clearActiveProgress() {
	if activeProgress != nil && atomic.LoadInt32(&activeProgress.active) == 1 {
		fmt.Fprint(os.Stderr, "\r\033[2K")
		atomic.StoreInt32(&activeProgress.active, 0)
	}
}

// redrawActiveProgress redraws the active progress bar after output.
// Caller MUST hold printMutex.
func redrawActiveProgress() {
	if activeProgress == nil || currentProgressMode() != progressTTY {
		return
	}
	if c := atomic.LoadInt64(&activeProgress.completed); c < activeProgress.total {
		activeProgress.renderLocked(c)
	}
}

// progress tracks completion of requests within a technique and reports it on
// stderr in whichever form suits the environment.
type progress struct {
	total     int64
	completed int64
	technique string
	barWidth  int
	mode      progressMode
	started   time.Time
	active    int32 // 1 if a bar line is currently on screen (TTY mode)

	milestoneMu   sync.Mutex
	nextMilestone int // index into plainMilestones
}

// newProgress creates a progress tracker for a technique. Pass 0 total to
// disable reporting for it.
func newProgress(technique string, total int) *progress {
	mode := currentProgressMode()
	p := &progress{
		total:     int64(total),
		technique: technique,
		barWidth:  25,
		mode:      mode,
		started:   time.Now(),
	}
	if total <= 0 || mode == progressOff {
		return p
	}

	switch mode {
	case progressTTY:
		printMutex.Lock()
		activeProgress = p
		printMutex.Unlock()
	case progressPlain:
		p.printPlainf("%s: %d requests", technique, total)
	case progressOff:
	}
	return p
}

// enabled reports whether this tracker should report anything.
func (p *progress) enabled() bool { return p.total > 0 && p.mode != progressOff }

// done records one completed request and reports progress.
func (p *progress) done() {
	if !p.enabled() {
		return
	}
	c := atomic.AddInt64(&p.completed, 1)

	switch p.mode {
	case progressTTY:
		printMutex.Lock()
		defer printMutex.Unlock()
		p.renderLocked(c)
	case progressPlain:
		p.reportMilestone(c)
	case progressOff:
	}
}

// finish reports the technique as complete and tears down any live bar.
func (p *progress) finish() {
	if !p.enabled() {
		return
	}

	switch p.mode {
	case progressTTY:
		printMutex.Lock()
		defer printMutex.Unlock()
		if atomic.LoadInt32(&p.active) == 1 {
			fmt.Fprint(os.Stderr, "\r\033[2K")
			atomic.StoreInt32(&p.active, 0)
		}
		if activeProgress == p {
			activeProgress = nil
		}
	case progressPlain:
		completed := atomic.LoadInt64(&p.completed)
		p.printPlainf("%s: done %d/%d in %s", p.technique, completed, p.total, formatProgressDuration(time.Since(p.started)))
	case progressOff:
	}
}

// reportMilestone emits a plain-mode percentage line the first time completion
// crosses each milestone. Techniques smaller than plainMilestoneMin report only
// their start and done lines.
func (p *progress) reportMilestone(completed int64) {
	if p.total < plainMilestoneMin {
		return
	}

	pct := int(completed * 100 / p.total)

	p.milestoneMu.Lock()
	reached := -1
	for p.nextMilestone < len(plainMilestones) && pct >= plainMilestones[p.nextMilestone] {
		reached = plainMilestones[p.nextMilestone]
		p.nextMilestone++
	}
	p.milestoneMu.Unlock()

	if reached < 0 {
		return
	}
	p.printPlainf("%s: %d%% (%d/%d)", p.technique, reached, completed, p.total)
}

// printPlain writes one append-only status line to stderr. It takes printMutex
// so a status line can never interleave with result output.
func (p *progress) printPlainf(format string, args ...any) {
	printMutex.Lock()
	defer printMutex.Unlock()
	fmt.Fprintf(os.Stderr, "[progress] "+format+"\n", args...)
}

// renderLocked draws the in-place bar. Caller MUST hold printMutex.
func (p *progress) renderLocked(completed int64) {
	total := p.total
	if total <= 0 {
		return
	}

	pct := float64(completed) / float64(total)
	if pct > 1 {
		pct = 1
	}

	filled := int(pct * float64(p.barWidth))
	empty := p.barWidth - filled

	bar := strings.Repeat("█", filled) + strings.Repeat("░", empty)
	fmt.Fprintf(os.Stderr, "\r\033[2K  %s %3.0f%% (%d/%d) %s", bar, pct*100, completed, total, p.technique)
	atomic.StoreInt32(&p.active, 1)
}

// formatProgressDuration renders an elapsed time compactly for status lines.
func formatProgressDuration(d time.Duration) string {
	if d < time.Second {
		return fmt.Sprintf("%dms", d.Milliseconds())
	}
	return fmt.Sprintf("%.1fs", d.Seconds())
}
