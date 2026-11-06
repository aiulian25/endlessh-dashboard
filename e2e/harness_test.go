package e2e

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

// This lifecycle regression needs no daemon or images. The fake Docker CLI
// creates project-owned inventory before failing, including a teardown failure.
const fakeDocker = `#!/usr/bin/env bash
set -eu
project=
for arg in "$@"; do
 if [[ $arg == label=com.docker.compose.project=* ]]; then project=${arg#*=}; project=${project#*=}; fi
done
if [[ $1 == compose ]]; then
 shift
 while (( $# )); do
  case $1 in --env-file|-f) shift 2;; -p) project=$2; shift 2;; *) break;; esac
 done
 dir=$MOCK_ROOT/$project
 case $1 in
 config|build) exit 0;;
 up)
 mkdir -p "$dir"
 for kind in container volume network; do echo "$project-$kind" > "$dir/$kind"; done
 if [[ $MOCK_SCENARIO == startup ]]; then exit 7; fi;;
 ps) echo "$project-container";;
 port) echo 127.0.0.1:34567;;
 logs) echo 'retained fixture logs';;
 down)
 if [[ $MOCK_SCENARIO == down ]]; then exit 9; fi
 rm -f "$dir/container" "$dir/volume" "$dir/network";;
 esac
 exit 0
fi
case $1 in
 inspect) echo "$E2E_EXPORTER_IMAGE";;
 image) echo 'fixture-image digest';;
 ps) [[ ! -f $MOCK_ROOT/$project/container ]] || cat "$MOCK_ROOT/$project/container";;
 volume|network)
 kind=$1
 if [[ $2 == ls ]]; then
 [[ ! -f $MOCK_ROOT/$project/$kind ]] || cat "$MOCK_ROOT/$project/$kind"
 else
 for id in "${@:3}"; do
  for file in "$MOCK_ROOT"/*/$kind; do
   if [[ -f $file && $(cat "$file") == "$id" ]]; then rm "$file"; fi
  done
 done
 fi;;
 rm)
 for id in "${@:3}"; do
  for file in "$MOCK_ROOT"/*/container; do
   if [[ -f $file && $(cat "$file") == "$id" ]]; then rm "$file"; fi
  done
 done;;
 *) exit 2;;
esac
`

func TestHarnessCleanup(t *testing.T) {
	runner, err := filepath.Abs("run.sh")
	if err != nil {
		t.Fatal(err)
	}
	for _, scenario := range []string{"success", "startup", "assertion", "signal", "interrupt", "down", "concurrent"} {
		t.Run(scenario, func(t *testing.T) {
			dir := t.TempDir()
			bin := filepath.Join(dir, "bin")
			state := filepath.Join(dir, "inventory")
			logs := filepath.Join(dir, "logs")
			if err := os.MkdirAll(bin, 0700); err != nil {
				t.Fatal(err)
			}
			sentinel := filepath.Join(state, "unrelated", "container")
			if err := os.MkdirAll(filepath.Dir(sentinel), 0700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(sentinel, []byte("preserve-me"), 0600); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(bin, "docker"), []byte(fakeDocker), 0700); err != nil {
				t.Fatal(err)
			}
			makeCommand := func(args ...string) *exec.Cmd {
				cmd := exec.Command("bash", append([]string{runner}, args...)...)
				cmd.Env = append(os.Environ(), "PATH="+bin+":"+os.Getenv("PATH"), "MOCK_ROOT="+state, "MOCK_SCENARIO="+scenario, "E2E_ARTIFACT_DIR="+logs)
				return cmd
			}
			var runDirs []os.DirEntry
			switch scenario {
			case "signal", "interrupt":
				cmd := makeCommand("sh", "-c", `touch "$MOCK_ROOT/test-start"; sleep 30`)
				if err := cmd.Start(); err != nil {
					t.Fatal(err)
				}
				done := make(chan error, 1)
				go func() { done <- cmd.Wait() }()
				deadline := time.Now().Add(5 * time.Second)
				for {
					if _, err := os.Stat(filepath.Join(state, "test-start")); err == nil {
						break
					}
					if time.Now().After(deadline) {
						cmd.Process.Signal(syscall.SIGTERM)
						t.Fatal("test never started")
					}
					time.Sleep(10 * time.Millisecond)
				}
				signal, want := syscall.SIGTERM, 143
				if scenario == "interrupt" {
					signal, want = syscall.SIGINT, 130
				}
				cmd.Process.Signal(signal)
				select {
				case err := <-done:
					if exit, ok := err.(*exec.ExitError); !ok || exit.ExitCode() != want {
						t.Fatalf("signal status: %v", err)
					}
				case <-time.After(5 * time.Second):
					cmd.Process.Kill()
					t.Fatal("signal did not complete cleanup")
				}
			case "concurrent":
				a, b := makeCommand("true"), makeCommand("true")
				if err := a.Start(); err != nil {
					t.Fatal(err)
				}
				if err := b.Start(); err != nil {
					t.Fatal(err)
				}
				if err := a.Wait(); err != nil {
					t.Fatal(err)
				}
				if err := b.Wait(); err != nil {
					t.Fatal(err)
				}
			default:
				command := "true"
				if scenario == "assertion" {
					command = "false"
				}
				output, err := makeCommand(command).CombinedOutput()
				want := 0
				if scenario == "startup" {
					want = 7
				}
				if scenario == "assertion" {
					want = 1
				}
				got := 0
				if err != nil {
					exit, ok := err.(*exec.ExitError)
					if !ok {
						t.Fatal(err)
					}
					got = exit.ExitCode()
				}
				if got != want {
					t.Fatalf("exit %d want %d: %s", got, want, output)
				}
			}
			runDirs, err = os.ReadDir(logs)
			if err != nil {
				t.Fatal(err)
			}
			expected := 1
			if scenario == "concurrent" {
				expected = 2
			}
			if len(runDirs) != expected {
				t.Fatalf("run directories=%d want %d", len(runDirs), expected)
			}
			projects := map[string]bool{}
			for _, entry := range runDirs {
				run := filepath.Join(logs, entry.Name())
				project, _ := os.ReadFile(filepath.Join(run, "project"))
				if projects[string(project)] {
					t.Fatal("concurrent project collision")
				}
				projects[string(project)] = true
				body, err := os.ReadFile(filepath.Join(run, "containers.log"))
				if err != nil || !strings.Contains(string(body), "retained fixture logs") {
					t.Fatalf("logs lost: %v", err)
				}
				remaining, err := os.ReadFile(filepath.Join(run, "remaining.log"))
				if err != nil || string(remaining) != "container: \nvolume: \nnetwork: \n" {
					t.Fatalf("remaining resources: %q %v", remaining, err)
				}
				owned := filepath.Join(state, strings.TrimSpace(string(project)))
				files, _ := os.ReadDir(owned)
				if len(files) != 0 {
					t.Fatalf("resource leak: %v", files)
				}
			}
			if body, _ := os.ReadFile(sentinel); string(body) != "preserve-me" {
				t.Fatal("unrelated inventory was touched")
			}
		})
	}
}
