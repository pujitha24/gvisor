// Copyright 2018 The gVisor Authors.
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

package futex

import (
	"math"
	"runtime"
	"testing"
	"unsafe"

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/atomicbitops"
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/errors/linuxerr"
	"gvisor.dev/gvisor/pkg/hostarch"
	"gvisor.dev/gvisor/pkg/sync"
)

// testData implements the Target interface, and allows us to
// treat the address passed for futex operations as an index in
// a byte slice for testing simplicity.
type testData struct {
	context.Context
	data []byte
}

const sizeofInt32 = 4

func newTestData(size uint) testData {
	return testData{
		data: make([]byte, size),
	}
}

func (t testData) SwapUint32(addr hostarch.Addr, new uint32) (uint32, error) {
	val := (*atomicbitops.Uint32)(unsafe.Pointer(&t.data[addr])).Swap(new)
	return val, nil
}

func (t testData) CompareAndSwapUint32(addr hostarch.Addr, old, new uint32) (uint32, error) {
	if (*atomicbitops.Uint32)(unsafe.Pointer(&t.data[addr])).CompareAndSwap(old, new) {
		return old, nil
	}
	return (*atomicbitops.Uint32)(unsafe.Pointer(&t.data[addr])).Load(), nil
}

func (t testData) LoadUint32(addr hostarch.Addr) (uint32, error) {
	return (*atomicbitops.Uint32)(unsafe.Pointer(&t.data[addr])).Load(), nil
}

func (t testData) GetSharedKey(addr hostarch.Addr) (Key, error) {
	return Key{
		Kind:   KindSharedMappable,
		Offset: uint64(addr),
	}, nil
}

func futexKind(private bool) string {
	if private {
		return "private"
	}
	return "shared"
}

func newPreparedTestWaiter(t *testing.T, m *Manager, ta Target, addr hostarch.Addr, private bool, val uint32, bitmask uint32) *Waiter {
	w := NewWaiter()
	if err := m.WaitPrepare(w, ta, addr, private, val, bitmask); err != nil {
		t.Fatalf("WaitPrepare failed: %v", err)
	}
	return w
}

func TestFutexWake(t *testing.T) {
	for _, private := range []bool{false, true} {
		t.Run(futexKind(private), func(t *testing.T) {
			m := NewManager()
			d := newTestData(sizeofInt32)

			// Start waiting for wakeup.
			w := newPreparedTestWaiter(t, m, d, 0, private, 0, ^uint32(0))
			defer m.WaitComplete(w, d)

			// Perform a wakeup.
			if n, err := m.Wake(d, 0, private, ^uint32(0), 1); err != nil || n != 1 {
				t.Errorf("Wake: got (%d, %v), wanted (1, nil)", n, err)
			}

			// Expect the waiter to have been woken.
			if !w.woken() {
				t.Error("waiter not woken")
			}
		})
	}
}

func TestFutexWakeBitmask(t *testing.T) {
	for _, private := range []bool{false, true} {
		t.Run(futexKind(private), func(t *testing.T) {
			m := NewManager()
			d := newTestData(sizeofInt32)

			// Start waiting for wakeup.
			w := newPreparedTestWaiter(t, m, d, 0, private, 0, 0x0000ffff)
			defer m.WaitComplete(w, d)

			// Perform a wakeup using the wrong bitmask.
			if n, err := m.Wake(d, 0, private, 0xffff0000, 1); err != nil || n != 0 {
				t.Errorf("Wake with non-matching bitmask: got (%d, %v), wanted (0, nil)", n, err)
			}

			// Expect the waiter to still be waiting.
			if w.woken() {
				t.Error("waiter woken unexpectedly")
			}

			// Perform a wakeup using the right bitmask.
			if n, err := m.Wake(d, 0, private, 0x00000001, 1); err != nil || n != 1 {
				t.Errorf("Wake with matching bitmask: got (%d, %v), wanted (1, nil)", n, err)
			}

			// Expect that the waiter was woken.
			if !w.woken() {
				t.Error("waiter not woken")
			}
		})
	}
}

func TestFutexWakeTwo(t *testing.T) {
	for _, private := range []bool{false, true} {
		t.Run(futexKind(private), func(t *testing.T) {
			m := NewManager()
			d := newTestData(sizeofInt32)

			// Start three waiters waiting for wakeup.
			var ws [3]*Waiter
			for i := range ws {
				ws[i] = newPreparedTestWaiter(t, m, d, 0, private, 0, ^uint32(0))
				defer m.WaitComplete(ws[i], d)
			}

			// Perform two wakeups.
			const wakeups = 2
			if n, err := m.Wake(d, 0, private, ^uint32(0), 2); err != nil || n != wakeups {
				t.Errorf("Wake: got (%d, %v), wanted (%d, nil)", n, err, wakeups)
			}

			// Expect that exactly two waiters were woken.
			// We don't get guarantees about exactly which two,
			// (although we expect them to be w1 and w2).
			awake := 0
			for i := range ws {
				if ws[i].woken() {
					awake++
				}
			}
			if awake != wakeups {
				t.Errorf("got %d woken waiters, wanted %d", awake, wakeups)
			}
		})
	}
}

func TestFutexWakeUnrelated(t *testing.T) {
	for _, private := range []bool{false, true} {
		t.Run(futexKind(private), func(t *testing.T) {
			m := NewManager()
			d := newTestData(2 * sizeofInt32)

			// Start two waiters waiting for wakeup on different addresses.
			w1 := newPreparedTestWaiter(t, m, d, 0*sizeofInt32, private, 0, ^uint32(0))
			defer m.WaitComplete(w1, d)
			w2 := newPreparedTestWaiter(t, m, d, 1*sizeofInt32, private, 0, ^uint32(0))
			defer m.WaitComplete(w2, d)

			// Perform two wakeups on the second address.
			if n, err := m.Wake(d, 1*sizeofInt32, private, ^uint32(0), 2); err != nil || n != 1 {
				t.Errorf("Wake: got (%d, %v), wanted (1, nil)", n, err)
			}

			// Expect that only the second waiter was woken.
			if w1.woken() {
				t.Error("w1 woken unexpectedly")
			}
			if !w2.woken() {
				t.Error("w2 not woken")
			}
		})
	}
}

func TestWakeOpEmpty(t *testing.T) {
	for _, private := range []bool{false, true} {
		t.Run(futexKind(private), func(t *testing.T) {
			m := NewManager()
			d := newTestData(2 * sizeofInt32)

			// Perform wakeups with no waiters.
			if n, err := m.WakeOp(d, 0, sizeofInt32, private, 10, 10, 0); err != nil || n != 0 {
				t.Fatalf("WakeOp: got (%d, %v), wanted (0, nil)", n, err)
			}
		})
	}
}

func TestWakeOpFirstNonEmpty(t *testing.T) {
	for _, private := range []bool{false, true} {
		t.Run(futexKind(private), func(t *testing.T) {
			m := NewManager()
			d := newTestData(8)

			// Add two waiters on address 0.
			w1 := newPreparedTestWaiter(t, m, d, 0, private, 0, ^uint32(0))
			defer m.WaitComplete(w1, d)
			w2 := newPreparedTestWaiter(t, m, d, 0, private, 0, ^uint32(0))
			defer m.WaitComplete(w2, d)

			// Perform 10 wakeups on address 0.
			if n, err := m.WakeOp(d, 0, sizeofInt32, private, 10, 0, 0); err != nil || n != 2 {
				t.Errorf("WakeOp: got (%d, %v), wanted (2, nil)", n, err)
			}

			// Expect that both waiters were woken.
			if !w1.woken() {
				t.Error("w1 not woken")
			}
			if !w2.woken() {
				t.Error("w2 not woken")
			}
		})
	}
}

func TestWakeOpSecondNonEmpty(t *testing.T) {
	for _, private := range []bool{false, true} {
		t.Run(futexKind(private), func(t *testing.T) {
			m := NewManager()
			d := newTestData(8)

			// Add two waiters on address sizeofInt32.
			w1 := newPreparedTestWaiter(t, m, d, sizeofInt32, private, 0, ^uint32(0))
			defer m.WaitComplete(w1, d)
			w2 := newPreparedTestWaiter(t, m, d, sizeofInt32, private, 0, ^uint32(0))
			defer m.WaitComplete(w2, d)

			// Perform 10 wakeups on address sizeofInt32 (contingent on
			// d.Op(0), which should succeed).
			if n, err := m.WakeOp(d, 0, sizeofInt32, private, 0, 10, 0); err != nil || n != 2 {
				t.Errorf("WakeOp: got (%d, %v), wanted (2, nil)", n, err)
			}

			// Expect that both waiters were woken.
			if !w1.woken() {
				t.Error("w1 not woken")
			}
			if !w2.woken() {
				t.Error("w2 not woken")
			}
		})
	}
}

func TestWakeOpSecondNonEmptyFailingOp(t *testing.T) {
	for _, private := range []bool{false, true} {
		t.Run(futexKind(private), func(t *testing.T) {
			m := NewManager()
			d := newTestData(8)

			// Add two waiters on address sizeofInt32.
			w1 := newPreparedTestWaiter(t, m, d, sizeofInt32, private, 0, ^uint32(0))
			defer m.WaitComplete(w1, d)
			w2 := newPreparedTestWaiter(t, m, d, sizeofInt32, private, 0, ^uint32(0))
			defer m.WaitComplete(w2, d)

			// Perform 10 wakeups on address sizeofInt32 (contingent on
			// d.Op(1), which should fail).
			if n, err := m.WakeOp(d, 0, sizeofInt32, private, 0, 10, 1); err != nil || n != 0 {
				t.Errorf("WakeOp: got (%d, %v), wanted (0, nil)", n, err)
			}

			// Expect that neither waiter was woken.
			if w1.woken() {
				t.Error("w1 woken unexpectedly")
			}
			if w2.woken() {
				t.Error("w2 woken unexpectedly")
			}
		})
	}
}

func TestWakeOpAllNonEmpty(t *testing.T) {
	for _, private := range []bool{false, true} {
		t.Run(futexKind(private), func(t *testing.T) {
			m := NewManager()
			d := newTestData(8)

			// Add two waiters on address 0.
			w1 := newPreparedTestWaiter(t, m, d, 0, private, 0, ^uint32(0))
			defer m.WaitComplete(w1, d)
			w2 := newPreparedTestWaiter(t, m, d, 0, private, 0, ^uint32(0))
			defer m.WaitComplete(w2, d)

			// Add two waiters on address sizeofInt32.
			w3 := newPreparedTestWaiter(t, m, d, sizeofInt32, private, 0, ^uint32(0))
			defer m.WaitComplete(w3, d)
			w4 := newPreparedTestWaiter(t, m, d, sizeofInt32, private, 0, ^uint32(0))
			defer m.WaitComplete(w4, d)

			// Perform 10 wakeups on address 0 (unconditionally), and 10
			// wakeups on address sizeofInt32 (contingent on d.Op(0), which
			// should succeed).
			if n, err := m.WakeOp(d, 0, sizeofInt32, private, 10, 10, 0); err != nil || n != 4 {
				t.Errorf("WakeOp: got (%d, %v), wanted (4, nil)", n, err)
			}

			// Expect that all waiters were woken.
			if !w1.woken() {
				t.Error("w1 not woken")
			}
			if !w2.woken() {
				t.Error("w2 not woken")
			}
			if !w3.woken() {
				t.Error("w3 not woken")
			}
			if !w4.woken() {
				t.Error("w4 not woken")
			}
		})
	}
}

func TestWakeOpAllNonEmptyFailingOp(t *testing.T) {
	for _, private := range []bool{false, true} {
		t.Run(futexKind(private), func(t *testing.T) {
			m := NewManager()
			d := newTestData(8)

			// Add two waiters on address 0.
			w1 := newPreparedTestWaiter(t, m, d, 0, private, 0, ^uint32(0))
			defer m.WaitComplete(w1, d)
			w2 := newPreparedTestWaiter(t, m, d, 0, private, 0, ^uint32(0))
			defer m.WaitComplete(w2, d)

			// Add two waiters on address sizeofInt32.
			w3 := newPreparedTestWaiter(t, m, d, sizeofInt32, private, 0, ^uint32(0))
			defer m.WaitComplete(w3, d)
			w4 := newPreparedTestWaiter(t, m, d, sizeofInt32, private, 0, ^uint32(0))
			defer m.WaitComplete(w4, d)

			// Perform 10 wakeups on address 0 (unconditionally), and 10
			// wakeups on address sizeofInt32 (contingent on d.Op(1), which
			// should fail).
			if n, err := m.WakeOp(d, 0, sizeofInt32, private, 10, 10, 1); err != nil || n != 2 {
				t.Errorf("WakeOp: got (%d, %v), wanted (2, nil)", n, err)
			}

			// Expect that only the first two waiters were woken.
			if !w1.woken() {
				t.Error("w1 not woken")
			}
			if !w2.woken() {
				t.Error("w2 not woken")
			}
			if w3.woken() {
				t.Error("w3 woken unexpectedly")
			}
			if w4.woken() {
				t.Error("w4 woken unexpectedly")
			}
		})
	}
}

func TestWakeOpSameAddress(t *testing.T) {
	for _, private := range []bool{false, true} {
		t.Run(futexKind(private), func(t *testing.T) {
			m := NewManager()
			d := newTestData(8)

			// Add four waiters on address 0.
			var ws [4]*Waiter
			for i := range ws {
				ws[i] = newPreparedTestWaiter(t, m, d, 0, private, 0, ^uint32(0))
				defer m.WaitComplete(ws[i], d)
			}

			// Perform 1 wakeup on address 0 (unconditionally), and 1 wakeup
			// on address 0 (contingent on d.Op(0), which should succeed).
			const wakeups = 2
			if n, err := m.WakeOp(d, 0, 0, private, 1, 1, 0); err != nil || n != wakeups {
				t.Errorf("WakeOp: got (%d, %v), wanted (%d, nil)", n, err, wakeups)
			}

			// Expect that exactly two waiters were woken.
			awake := 0
			for i := range ws {
				if ws[i].woken() {
					awake++
				}
			}
			if awake != wakeups {
				t.Errorf("got %d woken waiters, wanted %d", awake, wakeups)
			}
		})
	}
}

func TestWakeOpSameAddressFailingOp(t *testing.T) {
	for _, private := range []bool{false, true} {
		t.Run(futexKind(private), func(t *testing.T) {
			m := NewManager()
			d := newTestData(8)

			// Add four waiters on address 0.
			var ws [4]*Waiter
			for i := range ws {
				ws[i] = newPreparedTestWaiter(t, m, d, 0, private, 0, ^uint32(0))
				defer m.WaitComplete(ws[i], d)
			}

			// Perform 1 wakeup on address 0 (unconditionally), and 1 wakeup
			// on address 0 (contingent on d.Op(1), which should fail).
			const wakeups = 1
			if n, err := m.WakeOp(d, 0, 0, private, 1, 1, 1); err != nil || n != wakeups {
				t.Errorf("WakeOp: got (%d, %v), wanted (%d, nil)", n, err, wakeups)
			}

			// Expect that exactly one waiter was woken.
			awake := 0
			for i := range ws {
				if ws[i].woken() {
					awake++
				}
			}
			if awake != wakeups {
				t.Errorf("got %d woken waiters, wanted %d", awake, wakeups)
			}
		})
	}
}

const (
	testMutexSize            = sizeofInt32
	testMutexLocked   uint32 = 1
	testMutexUnlocked uint32 = 0
)

// testMutex ties together a testData slice, an address, and a
// futex manager in order to implement the sync.Locker interface.
// Beyond being used as a Locker, this is a simple mechanism for
// changing the underlying values for simpler tests.
type testMutex struct {
	a hostarch.Addr
	d testData
	m *Manager
}

func newTestMutex(addr hostarch.Addr, d testData, m *Manager) *testMutex {
	return &testMutex{a: addr, d: d, m: m}
}

// Lock acquires the testMutex.
// This may wait for it to be available via the futex manager.
func (t *testMutex) Lock() {
	for {
		// Attempt to grab the lock.
		if (*atomicbitops.Uint32)(unsafe.Pointer(&t.d.data[t.a])).CompareAndSwap(
			testMutexUnlocked,
			testMutexLocked) {
			// Lock held.
			return
		}

		// Wait for it to be "not locked".
		w := NewWaiter()
		err := t.m.WaitPrepare(w, t.d, t.a, true, testMutexLocked, ^uint32(0))
		if linuxerr.Equals(linuxerr.EAGAIN, err) {
			continue
		}
		if err != nil {
			// Should never happen.
			panic("WaitPrepare returned unexpected error: " + err.Error())
		}
		<-w.C
		t.m.WaitComplete(w, t.d)
	}
}

// Unlock releases the testMutex.
// This will notify any waiters via the futex manager.
func (t *testMutex) Unlock() {
	// Unlock.
	(*atomicbitops.Uint32)(unsafe.Pointer(&t.d.data[t.a])).Store(testMutexUnlocked)

	// Notify all waiters.
	t.m.Wake(t.d, t.a, true, ^uint32(0), math.MaxInt32)
}

// This function was shamelessly stolen from mutex_test.go.
func HammerMutex(l sync.Locker, loops int, cdone chan bool) {
	for i := 0; i < loops; i++ {
		l.Lock()
		runtime.Gosched()
		l.Unlock()
	}
	cdone <- true
}

func TestMutexStress(t *testing.T) {
	m := NewManager()
	d := newTestData(testMutexSize)
	tm := newTestMutex(0*testMutexSize, d, m)
	c := make(chan bool)

	for i := 0; i < 10; i++ {
		go HammerMutex(tm, 1000, c)
	}

	for i := 0; i < 10; i++ {
		<-c
	}
}

// encodeOp builds a FUTEX_WAKE_OP operation word.
func encodeOp(op, cmp, opArg, cmpArg uint32) uint32 {
	return op<<28 | cmp<<24 | (opArg&0xfff)<<12 | cmpArg&0xfff
}

func TestAtomicOpSigned(t *testing.T) {
	for _, tc := range []struct {
		name    string
		initial uint32
		op      uint32
		want    bool
		wantVal uint32
	}{
		{
			// The operation used by Qt 5.15.3's QSemaphore::release().
			name:    "ANDN shift 31, LT 0, negative old value",
			initial: 0x80000001,
			op:      encodeOp(linux.FUTEX_OP_ANDN|linux.FUTEX_OP_OPARG_SHIFT, linux.FUTEX_OP_CMP_LT, 31, 0),
			want:    true,
			wantVal: 1,
		},
		{
			name:    "ANDN shift 31, LT 0, positive old value",
			initial: 1,
			op:      encodeOp(linux.FUTEX_OP_ANDN|linux.FUTEX_OP_OPARG_SHIFT, linux.FUTEX_OP_CMP_LT, 31, 0),
			want:    false,
			wantVal: 1,
		},
		{
			name:    "SET -1",
			initial: 0,
			op:      encodeOp(linux.FUTEX_OP_SET, linux.FUTEX_OP_CMP_EQ, 0xfff, 0),
			want:    true,
			wantVal: 0xffffffff,
		},
		{
			name:    "ADD -1",
			initial: 5,
			op:      encodeOp(linux.FUTEX_OP_ADD, linux.FUTEX_OP_CMP_EQ, 0xfff, 5),
			want:    true,
			wantVal: 4,
		},
		{
			name:    "GE -1",
			initial: 0xffffffff,
			op:      encodeOp(linux.FUTEX_OP_OR, linux.FUTEX_OP_CMP_GE, 0, 0xfff),
			want:    true,
			wantVal: 0xffffffff,
		},
		{
			name:    "GT -1, negative shift count is masked",
			initial: 0,
			op:      encodeOp(linux.FUTEX_OP_OR|linux.FUTEX_OP_OPARG_SHIFT, linux.FUTEX_OP_CMP_GT, 0xfff, 0xfff),
			want:    true,
			wantVal: 1 << 31,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d := newTestData(sizeofInt32)
			d.SwapUint32(0, tc.initial)
			got, err := atomicOp(d, 0, tc.op)
			if err != nil || got != tc.want {
				t.Errorf("atomicOp: got (%v, %v), wanted (%v, nil)", got, err, tc.want)
			}
			if val, _ := d.LoadUint32(0); val != tc.wantVal {
				t.Errorf("value after atomicOp: got %#x, wanted %#x", val, tc.wantVal)
			}
		})
	}
}
