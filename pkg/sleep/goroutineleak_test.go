// Copyright 2026 The gVisor Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package sleep

import (
	"context"
	"io"
	"os"
	"os/exec"
	"runtime"
	"runtime/pprof"
	"strings"
	"testing"
	"time"
)

// parkedInNextWaker returns true if some goroutine is blocked in
// Sleeper.nextWaker. buf is scratch space for runtime.Stack.
func parkedInNextWaker(buf []byte) bool {
	n := runtime.Stack(buf, true)
	for _, g := range strings.Split(string(buf[:n]), "\n\n") {
		header, _, _ := strings.Cut(g, "\n")
		if strings.Contains(g, "(*Sleeper).nextWaker") && (strings.Contains(header, "[select") || strings.Contains(header, "[semacquire")) {
			return true
		}
	}
	return false
}

// The helper env var marks the subprocess that runs the actual check.
const goroutineLeakHelperEnv = "GVISOR_SLEEP_GOROUTINELEAK_HELPER"

// TestWakeAfterGoroutineLeakProfile checks that a parked Sleeper can still be
// woken after a goroutineleak profile has been collected. The check runs in a
// subprocess since the failure mode is a fatal runtime error.
func TestWakeAfterGoroutineLeakProfile(t *testing.T) {
	profile := pprof.Lookup("goroutineleak")
	if profile == nil {
		t.Skip("Go runtime does not provide goroutineleak profiling")
	}
	if os.Getenv(goroutineLeakHelperEnv) == "" {
		exe, err := os.Executable()
		if err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		cmd := exec.CommandContext(ctx, exe, "-test.run=^TestWakeAfterGoroutineLeakProfile$")
		cmd.Env = append(os.Environ(), goroutineLeakHelperEnv+"=1")
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("subprocess failed: %v\n%s", err, out)
		}
		return
	}

	var s Sleeper
	var w Waker
	s.AddWaker(&w)
	defer s.Done()
	done := make(chan struct{})
	go func() {
		s.Fetch(true)
		close(done)
	}()

	// Wait for the goroutine to actually park in Sleeper.nextWaker.
	buf := make([]byte, 1<<20)
	for deadline := time.Now().Add(10 * time.Second); !parkedInNextWaker(buf); runtime.Gosched() {
		if time.Now().After(deadline) {
			t.Fatal("sleeper did not park")
		}
	}
	if err := profile.WriteTo(io.Discard, 0); err != nil {
		t.Fatal(err)
	}
	w.Assert()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("sleeper did not wake")
	}
}
