// Package buildinfo identifies the exact source used for a release binary.
package buildinfo

import (
	"encoding/json"
	"io"
	"runtime"
	"runtime/debug"
)

var Version = "dev"
var Commit = "unknown"
var Built = "unknown"

type Info struct {
	Version  string `json:"version"`
	Commit   string `json:"commit"`
	Built    string `json:"built"`
	Go       string `json:"go"`
	Platform string `json:"platform"`
}

func Current() Info {
	commit := Commit
	if commit == "unknown" {
		if b, ok := debug.ReadBuildInfo(); ok {
			for _, s := range b.Settings {
				if s.Key == "vcs.revision" {
					commit = s.Value
				}
			}
		}
	}
	return Info{Version, commit, Built, runtime.Version(), runtime.GOOS + "/" + runtime.GOARCH}
}
func Write(w io.Writer) error { return json.NewEncoder(w).Encode(Current()) }
