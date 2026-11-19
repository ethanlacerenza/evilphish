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
	"encoding/json"
	"os"
)

// State is persisted to disk so a restart doesn't re-send already-forwarded
// captures into gophish, and doesn't re-scan evilginx sessions from id 1
// every time.
type State struct {
	LastSeenID int64 `json:"last_seen_id"`
	// ForwardedUpdateTime maps evilginx session_id -> the update_time we
	// already forwarded for it. A session row gets updated multiple times
	// as evilginx captures username, then password, then tokens; we only
	// re-forward when update_time has moved past what we last sent.
	ForwardedUpdateTime map[string]int64 `json:"forwarded_update_time"`
}

func LoadState(path string) (*State, error) {
	st := &State{ForwardedUpdateTime: map[string]int64{}}
	b, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return st, nil
		}
		return nil, err
	}
	if len(b) == 0 {
		return st, nil
	}
	if err := json.Unmarshal(b, st); err != nil {
		return nil, err
	}
	if st.ForwardedUpdateTime == nil {
		st.ForwardedUpdateTime = map[string]int64{}
	}
	return st, nil
}

func (s *State) Save(path string) error {
	b, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, b, 0o600)
}
