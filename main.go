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
//
// evilphish watches an evilginx3 sessions database (read-only) and, for each
// captured login it can correlate to a gophish campaign recipient (via the
// "rid" tracking parameter), replays the capture into gophish's own
// landing-page endpoint so it shows up as native "Submitted Data".
//
// Two ways to run:
//
//	./evilphish                 interactive shell (banner + live config)
//	./evilphish --headless      no shell, just forward (for systemd/services)
//	./evilphish -dump-schema    parse data.db, print a summary, exit
//
// The shell auto-disables itself when there is no TTY (e.g. under systemd),
// so the same binary works in both modes.
package main

import (
	"flag"
	"log"
	"os"
	"time"
)

func main() {
	configPath := flag.String("config", "config.json", "path to config JSON file (created/updated from the shell)")
	headless := flag.Bool("headless", false, "run without the interactive shell (for systemd / unattended use)")
	dumpSchema := flag.Bool("dump-schema", false, "parse the evilginx data.db and print a summary, then exit")
	showVersion := flag.Bool("version", false, "print version and exit")
	flag.Parse()

	if *showVersion {
		log.Printf("evilphish %s", VERSION)
		return
	}

	cfg, err := LoadConfig(*configPath)
	if err != nil {
		log.Fatalf("config error: %v", err)
	}

	if *dumpSchema {
		s := cfg.Snapshot()
		if s.EvilginxDBPath == "" {
			log.Fatalf("no evilginx_db_path configured")
		}
		schema, err := NewRESPAOFSource(s.EvilginxDBPath).DumpSchema()
		if err != nil {
			log.Fatalf("could not read %s: %v", s.EvilginxDBPath, err)
		}
		log.Printf("summary for %s:\n%s", s.EvilginxDBPath, schema)
		return
	}

	if *headless || !isInteractive() {
		runHeadless(cfg)
		return
	}
	runInteractive(cfg)
}

// isInteractive reports whether stdin is a real terminal. Dependency-free.
func isInteractive() bool {
	fi, err := os.Stdin.Stat()
	if err != nil {
		return false
	}
	return fi.Mode()&os.ModeCharDevice != 0
}

// runInteractive shows the banner and drops into the shell. The forwarder is
// NOT auto-started: the operator reviews config, runs 'test', then 'start'.
func runInteractive(cfg *Config) {
	Banner()

	term, err := NewTerminal(cfg, nil)
	if err != nil {
		log.Fatalf("terminal: %v", err)
	}
	defer term.Close()

	// wire the poller's log output through readline so the prompt stays clean
	poller := NewPoller(cfg, term.Logf)
	term.poller = poller

	term.DoWork()
}

// runHeadless starts the forwarder and blocks forever, for systemd/unattended
// use. It requires a complete config.
func runHeadless(cfg *Config) {
	ready, missing := cfg.Ready()
	if !ready {
		log.Fatalf("headless mode needs a complete config; missing: %v", missing)
	}

	poller := NewPoller(cfg, func(format string, a ...interface{}) { log.Printf(format, a...) })
	if err := poller.Start(); err != nil {
		log.Fatalf("start: %v", err)
	}

	s := cfg.Snapshot()
	if s.DryRun {
		log.Printf("DRY RUN: captures are logged but NOT sent. Set dry_run=false (or 'dryrun off' in the shell) to go live.")
	}
	log.Printf("evilphish %s headless: watching %s every %ds -> %s", VERSION, s.EvilginxDBPath, s.PollIntervalSeconds, s.GophishAPIBaseURL)

	for {
		time.Sleep(time.Hour) // the poller runs in its own goroutine
	}
}
