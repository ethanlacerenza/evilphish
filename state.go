package main

import (
	"encoding/json"
	"os"
)

// State is persisted to disk so a restart doesn't re-send already-forwarded
// captures into gophish, and doesn't re-scan evilginx sessions from id 1
// every time.
type State struct {
	LastSeenID int64            `json:"last_seen_id"`
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
