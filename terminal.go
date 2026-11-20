// evilphish — bridges evilginx3 captures into gophish
// Copyright (C) 2026  Ethan Lacerenza
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.
package main

import (
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"

	"github.com/chzyer/readline"
	"github.com/fatih/color"
)

type Terminal struct {
	cfg    *Config
	poller *Poller
	rl     *readline.Instance
}

func completer() *readline.PrefixCompleter {
	return readline.NewPrefixCompleter(
		readline.PcItem("config",
			readline.PcItem("gophish",
				readline.PcItem("api_url"),
				readline.PcItem("api_key"),
				readline.PcItem("phish_url"),
				readline.PcItem("insecure", readline.PcItem("true"), readline.PcItem("false")),
				readline.PcItem("cache"),
			),
			readline.PcItem("evilginx", readline.PcItem("db")),
			readline.PcItem("poll"),
			readline.PcItem("rid_param"),
			readline.PcItem("state_file"),
			readline.PcItem("useragent"),
			readline.PcItem("submit_insecure", readline.PcItem("true"), readline.PcItem("false")),
			readline.PcItem("mapping",
				readline.PcItem("username"), readline.PcItem("password"), readline.PcItem("tokens")),
		),
		readline.PcItem("dryrun", readline.PcItem("on"), readline.PcItem("off")),
		readline.PcItem("start"),
		readline.PcItem("stop"),
		readline.PcItem("restart"),
		readline.PcItem("status"),
		readline.PcItem("sessions"),
		readline.PcItem("test"),
		readline.PcItem("clear"),
		readline.PcItem("help"),
		readline.PcItem("exit"),
		readline.PcItem("quit"),
	)
}

func NewTerminal(cfg *Config, poller *Poller) (*Terminal, error) {
	rl, err := readline.NewEx(&readline.Config{
		Prompt:            "evilphish > ",
		AutoComplete:      completer(),
		InterruptPrompt:   "^C",
		EOFPrompt:         "exit",
		HistorySearchFold: true,
	})
	if err != nil {
		return nil, err
	}
	return &Terminal{cfg: cfg, poller: poller, rl: rl}, nil
}

func (t *Terminal) Close() { t.rl.Close() }

// Logf writes a timestamped line without clobbering the readline prompt.
func (t *Terminal) Logf(format string, a ...interface{}) {
	ts := color.New(color.FgHiBlack).Sprintf("[%s]", time.Now().Format("15:04:05"))
	fmt.Fprintf(t.rl.Stdout(), "%s %s\n", ts, fmt.Sprintf(format, a...))
}

func (t *Terminal) out(format string, a ...interface{}) {
	fmt.Fprintf(t.rl.Stdout(), format+"\n", a...)
}

func (t *Terminal) DoWork() {
	t.printHints()

	for {
		line, err := t.rl.Readline()
		if err == readline.ErrInterrupt {
			t.out(color.HiBlackString("type 'exit' to quit"))
			continue
		} else if err == io.EOF {
			break
		}

		args := strings.Fields(strings.TrimSpace(line))
		if len(args) == 0 {
			continue
		}

		switch args[0] {
		case "config":
			t.handleConfig(args[1:])
		case "dryrun":
			t.handleDryRun(args[1:])
		case "start":
			t.handleStart()
		case "stop":
			t.poller.Stop()
			t.ok("poller stopped")
		case "restart":
			t.handleRestart()
		case "status":
			t.printStatus()
		case "sessions":
			t.printSessions()
		case "test":
			t.testGophish()
		case "clear":
			readline.ClearScreen(color.Output)
		case "help", "?":
			t.printHelp()
		case "exit", "quit", "q":
			t.poller.Stop()
			return
		default:
			t.err("unknown command: %s  (try 'help')", args[0])
		}
	}
}

// --- command handlers ------------------------------------------------

func (t *Terminal) handleStart() {
	ready, missing := t.cfg.Ready()
	if !ready {
		t.err("not ready — set first: %s", strings.Join(missing, ", "))
		return
	}
	if t.poller.IsRunning() {
		t.out(color.HiBlackString("poller already running"))
		return
	}
	if err := t.poller.Start(); err != nil {
		t.err("start: %v", err)
		return
	}
	mode := "LIVE"
	if t.cfg.IsDryRun() {
		mode = "DRY RUN"
	}
	t.ok("poller started (%s, every %s)", mode, t.cfg.Interval())
}

func (t *Terminal) handleRestart() {
	if err := t.poller.Restart(); err != nil {
		t.err("restart: %v", err)
		return
	}
	t.ok("poller restarted — connection settings reloaded")
}

func (t *Terminal) handleDryRun(args []string) {
	if len(args) != 1 {
		t.err("usage: dryrun on|off")
		return
	}
	switch args[0] {
	case "on":
		t.cfg.SetDryRun(true)
		t.ok("dry-run ON — captures are logged, nothing is sent to gophish")
	case "off":
		t.cfg.SetDryRun(false)
		t.warn("dry-run OFF — captures WILL be injected into gophish")
	default:
		t.err("usage: dryrun on|off")
	}
}

func (t *Terminal) handleConfig(args []string) {
	if len(args) == 0 {
		t.printConfig()
		return
	}

	// forms with explicit section
	switch args[0] {
	case "gophish":
		if len(args) >= 2 {
			t.configGophish(args[1:])
			return
		}
	case "evilginx":
		if len(args) == 3 && args[1] == "db" {
			t.cfg.SetEvilginxDBPath(args[2])
			t.saved("evilginx db path", true)
			return
		}
	case "poll":
		if len(args) == 2 {
			n, err := strconv.Atoi(args[1])
			if err != nil || n <= 0 {
				t.err("poll must be a positive number of seconds")
				return
			}
			t.cfg.SetPollInterval(n)
			t.saved("poll interval", false)
			return
		}
	case "rid_param":
		if len(args) == 2 {
			t.cfg.SetRidParam(args[1])
			t.saved("rid param", false)
			return
		}
	case "state_file":
		if len(args) == 2 {
			t.cfg.SetStateFilePath(args[1])
			t.saved("state file", true)
			return
		}
	case "useragent":
		if len(args) >= 2 {
			t.cfg.SetSubmitUserAgent(strings.Join(args[1:], " "))
			t.saved("submit user-agent", false)
			return
		}
	case "submit_insecure":
		if len(args) == 2 {
			b, ok := parseBool(args[1])
			if !ok {
				t.err("usage: config submit_insecure true|false")
				return
			}
			t.cfg.SetSubmitInsecureTLS(b)
			t.saved("submit insecure-tls", true)
			return
		}
	case "mapping":
		// config mapping <field> <template...>   (empty template = delete)
		if len(args) >= 2 {
			field := args[1]
			tmpl := strings.Join(args[2:], " ")
			t.cfg.SetFormField(field, tmpl)
			if tmpl == "" {
				t.ok("mapping %q removed", field)
			} else {
				t.saved("form mapping", false)
			}
			return
		}
	}
	t.err("invalid syntax — 'help' for the config reference")
}

func (t *Terminal) configGophish(args []string) {
	switch args[0] {
	case "api_url":
		if len(args) == 2 {
			t.cfg.SetGophishAPIBaseURL(args[1])
			t.saved("gophish api url", true)
			return
		}
	case "api_key":
		if len(args) == 2 {
			t.cfg.SetGophishAPIKey(args[1])
			t.saved("gophish api key", true)
			return
		}
	case "phish_url":
		if len(args) == 2 {
			t.cfg.SetGophishPhishURL(args[1])
			t.saved("gophish phish url", false)
			return
		}
	case "insecure":
		if len(args) == 2 {
			b, ok := parseBool(args[1])
			if !ok {
				break
			}
			t.cfg.SetGophishInsecureTLS(b)
			t.saved("gophish insecure-tls", true)
			return
		}
	case "cache":
		if len(args) == 2 {
			n, err := strconv.Atoi(args[1])
			if err != nil || n <= 0 {
				t.err("cache must be a positive number of seconds")
				return
			}
			t.cfg.SetCampaignCache(n)
			t.saved("campaign cache", true)
			return
		}
	case "test":
		t.testGophish()
		return
	}
	t.err("invalid syntax — 'help' for the config reference")
}

// --- printers --------------------------------------------------------

func (t *Terminal) printConfig() {
	s := t.cfg.Snapshot()
	keys := []string{
		"evilginx db", "poll interval", "rid param",
		"gophish api url", "gophish api key", "gophish insecure",
		"gophish phish url", "campaign cache",
		"submit insecure", "submit user-agent",
		"state file", "dry run",
	}
	vals := []string{
		s.EvilginxDBPath,
		fmt.Sprintf("%ds", s.PollIntervalSeconds),
		s.RidQueryParam,
		s.GophishAPIBaseURL,
		mask(s.GophishAPIKey),
		strconv.FormatBool(s.GophishInsecureTLS),
		s.GophishPhishURL,
		fmt.Sprintf("%ds", s.CampaignCacheSeconds),
		strconv.FormatBool(s.SubmitInsecureTLS),
		s.SubmitUserAgentFallback,
		s.StateFilePath,
		boolColor(s.DryRun, "on (safe)", "OFF (live!)"),
	}
	fmt.Fprintf(t.rl.Stdout(), "\n%s\n", AsRows(keys, vals))

	// form mapping as its own little block
	if len(s.FormFieldMapping) > 0 {
		var mk, mv []string
		for k, v := range s.FormFieldMapping {
			mk = append(mk, "map "+k)
			mv = append(mv, v)
		}
		fmt.Fprintf(t.rl.Stdout(), "%s\n", AsRows(mk, mv))
	}
}

func (t *Terminal) printStatus() {
	st := t.poller.Stats()
	run := color.New(color.FgHiRed).Sprint("stopped")
	if st.Running {
		run = color.New(color.FgHiGreen).Sprint("running")
	}
	mode := "live"
	if t.cfg.IsDryRun() {
		mode = "dry-run"
	}
	keys := []string{"poller", "mode", "interval", "forwarded", "dry-run hits", "skipped", "sessions seen", "last run", "last error"}
	last := "-"
	if !st.LastRun.IsZero() {
		last = st.LastRun.Format("15:04:05")
	}
	lerr := "-"
	if st.LastErr != "" {
		lerr = fmt.Sprintf("%s (%s)", st.LastErr, st.LastErrTime.Format("15:04:05"))
	}
	vals := []string{
		run, mode, t.cfg.Interval().String(),
		strconv.Itoa(st.Forwarded), strconv.Itoa(st.DryRunHits),
		strconv.Itoa(st.Skipped), strconv.Itoa(st.Sessions),
		last, lerr,
	}
	fmt.Fprintf(t.rl.Stdout(), "\n%s\n", AsRows(keys, vals))
}

func (t *Terminal) printSessions() {
	s := t.cfg.Snapshot()
	if s.EvilginxDBPath == "" {
		t.err("set the evilginx db path first: config evilginx db <path>")
		return
	}
	src := NewRESPAOFSource(s.EvilginxDBPath)
	summary, err := src.DumpSchema()
	if err != nil {
		t.err("reading %s: %v", s.EvilginxDBPath, err)
		return
	}
	fmt.Fprintf(t.rl.Stdout(), "\n%s\n", summary)
}

func (t *Terminal) testGophish() {
	s := t.cfg.Snapshot()
	if s.GophishAPIBaseURL == "" || s.GophishAPIKey == "" {
		t.err("set gophish api_url and api_key first")
		return
	}
	t.out(color.HiBlackString("testing %s ...", s.GophishAPIBaseURL))
	gp := NewGophishClient(s)
	n, err := gp.Test()
	if err != nil {
		t.err("gophish: %v", err)
		return
	}
	t.ok("gophish reachable — %d campaign(s) visible with this API key", n)
}

func (t *Terminal) printHints() {
	ready, missing := t.cfg.Ready()
	if ready {
		t.out(color.HiBlackString("config looks complete. 'test' to verify gophish, then 'start'. 'help' for commands."))
	} else {
		t.out(color.HiBlackString("first run: set %s — see 'help'. Nothing is sent until you 'start' (dry-run is ON by default).",
			strings.Join(missing, ", ")))
	}
}

func (t *Terminal) printHelp() {
	h := color.New(color.FgHiWhite).Sprint
	d := color.New(color.FgHiBlack).Sprint
	fmt.Fprintf(t.rl.Stdout(), `
%s
  %s                 show / change all settings (saved to disk automatically)
  %s   set gophish admin API base url
  %s   set gophish API key
  %s  gophish phish server (where captures are POSTed)
  %s   gophish self-signed admin cert (yes/no)
  %s         path to evilginx data.db
  %s             re-scan interval in seconds
  %s        gophish tracking param name (default: rid)
  %s  map a gophish form field to a capture template
                             placeholders: {{username}} {{password}} {{tokens}}
                             {{session_id}} {{phishlet}} {{remote_addr}} {{update_time}}
                             (empty template removes the mapping)

%s
  %s                simulate: log captures, never send   (default ON)
  %s               go live: inject captures into gophish

%s
  %s                      verify gophish is reachable with the API key
  %s                  list sessions currently in evilginx's data.db
  %s                     start the background forwarder
  %s                      stop it
  %s                   stop + reload connection settings
  %s                    running state, counters, last error
  %s                     redraw screen
  %s                      quit

%s
`,
		h("CONFIG"),
		d("config"),
		d("config gophish api_url <url>"),
		d("config gophish api_key <key>"),
		d("config gophish phish_url <url>"),
		d("config gophish insecure true|false"),
		d("config evilginx db <path>"),
		d("config poll <seconds>"),
		d("config rid_param <name>"),
		d("config mapping <field> <tmpl>"),
		h("MODE"),
		d("dryrun on"),
		d("dryrun off"),
		h("RUN"),
		d("test"),
		d("sessions"),
		d("start"),
		d("stop"),
		d("restart"),
		d("status"),
		d("clear"),
		d("exit"),
		d("changes to gophish url/key/tls, evilginx db and state file need a 'restart' while running."),
	)
}

// --- small helpers ---------------------------------------------------

func (t *Terminal) ok(format string, a ...interface{}) {
	fmt.Fprintf(t.rl.Stdout(), "%s %s\n", color.HiGreenString("[+]"), fmt.Sprintf(format, a...))
}
func (t *Terminal) warn(format string, a ...interface{}) {
	fmt.Fprintf(t.rl.Stdout(), "%s %s\n", color.HiYellowString("[!]"), fmt.Sprintf(format, a...))
}
func (t *Terminal) err(format string, a ...interface{}) {
	fmt.Fprintf(t.rl.Stdout(), "%s %s\n", color.HiRedString("[-]"), fmt.Sprintf(format, a...))
}

// saved acknowledges a setting change and nudges for a restart if the change
// is connection-level and the poller is running.
func (t *Terminal) saved(what string, connLevel bool) {
	t.ok("%s saved", what)
	if connLevel && t.poller.IsRunning() {
		t.warn("poller is running — 'restart' to apply the new %s", what)
	}
}

func mask(s string) string {
	if s == "" {
		return color.HiBlackString("<empty>")
	}
	if len(s) <= 4 {
		return "****"
	}
	return "****" + s[len(s)-4:]
}

func boolColor(v bool, onText, offText string) string {
	if v {
		return color.HiGreenString(onText)
	}
	return color.HiRedString(offText)
}

func parseBool(s string) (bool, bool) {
	switch strings.ToLower(s) {
	case "true", "on", "yes", "1":
		return true, true
	case "false", "off", "no", "0":
		return false, true
	}
	return false, false
}
