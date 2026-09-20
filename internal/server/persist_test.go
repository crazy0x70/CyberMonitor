package server

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestLoadPersistedDataRecovery(t *testing.T) {
	for _, mainState := range []string{"valid", "corrupt", "absent"} {
		for _, backupState := range []string{"valid", "corrupt", "absent"} {
			t.Run(mainState+"_"+backupState, func(t *testing.T) {
				path := filepath.Join(t.TempDir(), "state.json")
				backupPath := path + ".bak"
				writeFixture := func(path, state, title string) []byte {
					t.Helper()
					if state == "absent" {
						return nil
					}
					raw := []byte("{broken-" + title)
					if state == "valid" {
						var err error
						raw, err = json.Marshal(PersistedData{Settings: Settings{SiteTitle: title, AdminPass: "preserve-hash", AgentToken: "preserve-token"}, PendingHistoryDeletes: []string{"node-one"}})
						if err != nil {
							t.Fatal(err)
						}
					}
					if err := os.WriteFile(path, raw, 0600); err != nil {
						t.Fatal(err)
					}
					return raw
				}
				mainRaw := writeFixture(path, mainState, "main")
				backupRaw := writeFixture(backupPath, backupState, "backup")
				got, loaded, err := loadPersistedData(path)
				wantLoaded := mainState == "valid" || backupState == "valid"
				wantError := !wantLoaded && (mainState == "corrupt" || backupState == "corrupt")
				if loaded != wantLoaded || (err != nil) != wantError {
					t.Fatalf("loaded=%v err=%v; want loaded=%v error=%v", loaded, err, wantLoaded, wantError)
				}
				if wantError {
					var syntaxErr *json.SyntaxError
					if !errors.As(err, &syntaxErr) {
						t.Errorf("lost JSON error cause: %v", err)
					}
					if mainState == "corrupt" && !strings.Contains(err.Error(), "读取 "+path+" 失败:") {
						t.Errorf("missing main path: %v", err)
					}
					if backupState == "corrupt" && !strings.Contains(err.Error(), backupPath) {
						t.Errorf("missing backup path: %v", err)
					}
					if mainState == "corrupt" && backupState == "corrupt" {
						joined, ok := err.(interface{ Unwrap() []error })
						if !ok || len(joined.Unwrap()) != 2 {
							t.Fatalf("expected both file errors: %v", err)
						}
						for _, cause := range joined.Unwrap() {
							var causeSyntaxErr *json.SyntaxError
							if !errors.As(cause, &causeSyntaxErr) {
								t.Errorf("lost JSON cause in joined error: %v", cause)
							}
						}
					}
				}
				assertBytes := func(path string, want []byte) {
					t.Helper()
					raw, err := os.ReadFile(path)
					if want == nil {
						if !os.IsNotExist(err) {
							t.Errorf("expected absent %s, got %v", path, err)
						}
						return
					}
					if err != nil || !bytes.Equal(raw, want) {
						t.Errorf("file changed %s: %q, %v", path, raw, err)
					}
				}
				assertBytes(backupPath, backupRaw)
				if mainState == "corrupt" && backupState == "valid" {
					assertBytes(path, nil)
				} else {
					assertBytes(path, mainRaw)
				}
				if !wantLoaded {
					return
				}
				title := "main"
				if mainState != "valid" {
					title = "backup"
				}
				if got.Settings.SiteTitle != title || got.Settings.AdminPass != "preserve-hash" || got.Settings.AgentToken != "preserve-token" || !reflect.DeepEqual(got.PendingHistoryDeletes, []string{"node-one"}) {
					t.Fatalf("lost persisted content: %+v", got)
				}
				if mainState != "valid" {
					if err := savePersistedData(path, got); err != nil {
						t.Fatal(err)
					}
					reloaded, ok, err := readPersistedDataFile(path)
					if err != nil || !ok || !reflect.DeepEqual(reloaded, got) {
						t.Fatalf("writeback mismatch: %+v, %v, %v", reloaded, ok, err)
					}
					assertBytes(backupPath, backupRaw)
				}
			})
		}
	}
}
