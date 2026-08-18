# UefiBootServicesTableLibHost — Event/Timer/TPL Design

## Overview

This library provides a host-based mock implementation of UEFI Boot Services
event, timer, and TPL APIs for AFL++ fuzz testing. The mock uses a
**queue-based dispatch model** that matches real edk2 DxeMain semantics.

The fundamental challenge: real edk2 relies on **hardware timer interrupts**
(8254/HPET/APIC) that fire asynchronously to drive timer events. We have no
hardware — everything is deterministic and single-threaded. This document
classifies each API by whether it **simulates async interrupt behavior**
(mock-only) or **matches real edk2 synchronous dispatch** (spec-compliant).

---

## Async Interrupt Simulation (Mock-Only — No Real edk2 Equivalent)

In real edk2, a hardware timer ISR signals expired timer events, and when
the interrupt returns and TPL drops, `CoreRestoreTpl` dispatches them. These
mock APIs substitute for that asynchronous hardware:

### `MockFuzzContextPumpEvents(Ctx)` — Central Fake-Async Driver

**Simulates:** "Time passes, interrupts fire between API calls."

- Consumes a `UINT16` fuzz bitmask to decide which registered events to
  `gBS->SignalEvent()`.
- Calls `TimerAdvanceFn` (= `MockTimerAdvance`) to advance simulated time.
- Harnesses call this at strategic points where real edk2 would rely on the
  timer ISR (e.g., between protocol calls, after transmit, during polling
  loops).
- **Source:** `FuzzContextLib/FuzzContextLib.c`

### `MockTimerAdvance(Microseconds)` / `MockTimerAdvance100ns(Time100ns)` — Simulated Timer ISR

**Simulates:** Hardware timer interrupt service routine.

- Increments `gSimulatedSystemTime`.
- `RaiseTpl(HIGH) → FireExpiredTimers() → RestoreTpl(Original)`.
- The Raise/Restore pattern mirrors the real ISR: timers enqueue at HIGH,
  dispatch when TPL drops.
- **Source:** `EventHost.c`

### `MockTimerInit()` — One-Time Timer Setup

**Simulates:** Hardware timer initialization.

- Registers `MockTimerAdvance` as `Pool->TimerAdvanceFn` so the pump can
  advance time automatically.
- Idempotent. Called once before the AFL forkserver starts.
- **Source:** `EventHost.c`

### `MockFuzzContextRegisterPumpEvent()` / `UnregisterPumpEvent()`

**Simulates:** Registering which events the "hardware" can trigger.

- Manages the set of events that `MockFuzzContextPumpEvents` selects from
  via the fuzz bitmask.
- **Source:** `FuzzContextLib/FuzzContextLib.c`

### `gMockTimerFireOnSetTimer` (default: `TRUE`) — Fuzzing Shortcut

**No edk2 equivalent.** When `TRUE`, `CoreSetTimer()` fires expired
callbacks immediately on arming. In real edk2, `SetTimer` only arms; the
hardware fires later. Ensures timer handler code gets coverage without
requiring time advance.

- **Source:** `EventHost.c`

### Auto-Pump Infrastructure

- **`gMockAutoPumpOnRestoreTpl`** (default: `TRUE`) — Flag controlling
  whether dropping TPL to `TPL_APPLICATION` triggers a pump.
- **`mAutoPumpInProgress`** — Re-entrancy guard preventing recursive pumps.
- **`MockEventSetAutoPumpOnRestoreTpl(Enable)`** — Enable/disable auto-pump.
- **`MockTplResetAutoPumpState()`** — Reset guard + re-enable for new iteration.
- **`MockEventSetPumpContext(Ctx)`** / **`gMockEventPumpContext`** — Set the
  fuzz context used by auto-pump and `CoreCloseEvent` auto-unregister.
- **Source:** `Tpl.c`, `EventHost.c`

---

## Synchronous Dispatch (Matches Real edk2)

These follow the same queue-then-dispatch model as real edk2 DxeMain. Their
behavior is spec-compliant per UEFI Specification 2.10A §7.1.

### `CoreSignalEvent()` — §7.1.4

**edk2 equivalent:** `CoreSignalEvent` (MdeModulePkg/Core/Dxe/Event/Event.c)

- `RaiseTpl(HIGH) → MockEventSignal(queue) → RestoreTpl(Original)`.
- RestoreTpl dispatches queued events when TPL drops.

### `CoreRestoreTpl(NewTpl)` — §7.1.9

**edk2 equivalent:** `CoreRestoreTpl` (MdeModulePkg/Core/Dxe/Event/Tpl.c)

```c
while (gEventPending != 0) {
    PendingTpl = HighBitSet64(gEventPending);
    if (PendingTpl <= NewTpl) break;
    gEfiCurrentTpl = PendingTpl;
    MockDispatchEventNotifies(gEfiCurrentTpl);
}
gEfiCurrentTpl = NewTpl;
```

- Walks `gEventPending` bitmask highest→lowest, dispatches at each TPL.
- Stack depth bounded at 4 (one per TPL level).

### `CoreRaiseTpl(NewTpl)` — §7.1.8

**edk2 equivalent:** `CoreRaiseTpl` (MdeModulePkg/Core/Dxe/Event/Tpl.c)

- Pure bookkeeping (no interrupt disable in single-threaded host).
- ASSERT on `OldTpl > NewTpl`.

### `MockEventSignal()` — Internal Queue-Only

**edk2 equivalent:** `CoreNotifySignalEvent`

- Sets `NotifyPending = TRUE` + `gEventPending |= (1 << NotifyTpl)`.
- **Never calls the callback directly.** Queue-only.

### `MockDispatchEventNotifies(Tpl)` — Per-TPL Dispatch

**edk2 equivalent:** `CoreDispatchEventNotifies`

- Iterates events at the given TPL, fires pending callbacks.
- Loops until stable (no new pending events at this TPL).
- Clears `gEventPending` bit when no more pending events at that TPL.

### `MockDpcQueueDpc()` — DPC Enqueue

**edk2 equivalent:** `DpcQueueDpc` (NetworkPkg/DpcDxe)

- `RaiseTpl(HIGH) → add to queue → RestoreTpl(Original)`.
- **No auto-drain.** Events dispatch only via explicit `DispatchDpc()`.

### `MockDpcDispatchDpc()` — DPC Explicit Drain

**edk2 equivalent:** `DpcDispatchDpc` (NetworkPkg/DpcDxe)

- Explicit iterative drain from HIGH TPL down.
- Called by driver code only, never automatically.

### Standard UEFI Boot Services (Spec-Compliant)

| API | Spec Section | Notes |
|-----|-------------|-------|
| `CoreCreateEvent` | §7.1.1 | Slot-based allocation (deviation: fixed array vs dynamic) |
| `CoreCreateEventEx` | §7.1.2 | EventGroup support |
| `CoreCloseEvent` | §7.1.3 | Enhanced with close-listeners for harness cleanup |
| `CoreSetTimer` | §7.1.7 | Arming matches spec; fire-on-set is deviation above |
| `CoreWaitForEvent` | §7.1.5 | Polls notify-wait events |
| `CoreCheckEvent` | §7.1.6 | Non-blocking check |

---

## Key Architectural Insight

```
Real edk2:
  Hardware Timer ISR ──(async)──► CoreSignalEvent ──► queue ──► CoreRestoreTpl dispatches

HBFAplus Mock:
  MockFuzzContextPumpEvents() ──(explicit)──► gBS->SignalEvent ──► queue ──► CoreRestoreTpl dispatches
  MockTimerAdvance()          ──(explicit)──► RaiseTpl(HIGH) → FireExpiredTimers → RestoreTpl dispatches
```

Everything from the queuing mechanism onward (`MockEventSignal` →
`gEventPending` → `CoreRestoreTpl` dispatch loop) is **identical** to real
edk2. The only difference is **what triggers the initial signal**: real
hardware interrupts vs. explicit harness calls / fuzz-driven pump.

---

## Source Files

| File | Role |
|------|------|
| `EventHost.c` | Event system: create/close/signal/timer, MockEventSignal, MockDispatchEventNotifies, MockTimerAdvance, FireExpiredTimers |
| `Tpl.c` | TPL management: CoreRaiseTpl, CoreRestoreTpl (dispatch loop), auto-pump infrastructure |
| `Event.h` | MOCK_EVENT struct, timer declarations, extern globals |
| `DxeMain.h` | Shared header for Boot Services table setup |
| `FuzzContextLib/FuzzContextLib.c` | MockFuzzContextPumpEvents, pump event registration |
| `MockgEfiDpcProtocolGuid.c` | MockDpcQueueDpc, MockDpcDispatchDpc |

## Globals

| Global | Type | Purpose |
|--------|------|---------|
| `gEventPending` | `UINTN` (bitmask) | Bit N set = events pending at TPL N |
| `gEfiCurrentTpl` | `EFI_TPL` | Current task priority level |
| `gSimulatedSystemTime` | `UINT64` | Simulated time in 100ns units |
| `gMockTimerFireOnSetTimer` | `BOOLEAN` | Fire timers immediately on SetTimer |
| `gMockAutoPumpOnRestoreTpl` | `BOOLEAN` | Auto-pump on TPL drop to APPLICATION |
| `gMockEventPumpContext` | `MOCK_FUZZ_CONTEXT*` | Pump context for auto-unregister |
