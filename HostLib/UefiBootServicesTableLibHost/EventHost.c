/** @file EventHost.c
    Host-compatible implementation of UEFI Boot Services event and timer functions.

    Reference: UEFI Specification 2.10A, Section 7.1
               "Event, Timer, and Task Priority Services"
               https://uefi.org/specs/UEFI/2.10_A/07_Services_Boot_Services.html

    This file provides mock implementations of the following Boot Services,
    with the corresponding UEFI Spec section noted:

      Function             Spec Section   Mock Entry Point
      -------------------  ------------   ----------------
      CreateEvent          §7.1.1         CoreCreateEvent()
      CreateEventEx        §7.1.2         CoreCreateEventEx()
      CloseEvent           §7.1.3         CoreCloseEvent()
      SignalEvent          §7.1.4         CoreSignalEvent()
      WaitForEvent         §7.1.5         CoreWaitForEvent()
      CheckEvent           §7.1.6         CoreCheckEvent()
      SetTimer             §7.1.7         CoreSetTimer()

    Plus deterministic timer simulation (no spec equivalent — mock-only):
      MockTimerInit / MockTimerReset
      MockTimerAdvance / MockTimerAdvance100ns
      MockTimerGetSystemTime
      Fire-on-SetTimer (callbacks fire immediately when SetTimer is called)

    Intentional Deviations from UEFI Spec (for host-based fuzzing):

      1. Queue-based signal dispatch (§7.1.4 compliance):
         Matches real edk2: CoreSignalEvent raises to TPL_HIGH_LEVEL,
         queues the event (MockEventSignal sets NotifyPending +
         gEventPending bit), then RestoreTpl dispatches pending events
         iteratively at their NotifyTpl level.  Stack depth is bounded
         at 4 (one per TPL level) — events at the same or lower TPL
         are queued and processed by the outer iterative loop, not
         dispatched recursively.

      2. No signal deduplication needed (§7.1.4):
         Spec says if an event is already signaled, the notification
         function is not re-queued.  We allow re-queuing (set pending
         again); this is conservative and doesn't cause issues because
         dispatch clears pending before invoking the callback.

      3. Event dispatch on RestoreTPL (§7.1.9 compliance):
         Matches real edk2: CoreRestoreTpl walks gEventPending bitmask
         from highest to lowest TPL, dispatching pending events at each
         level via MockDispatchEventNotifies().  gEfiCurrentTpl is set
         to PendingTpl during dispatch so callbacks run at their event's
         NotifyTpl level.

      4. No event group propagation (§7.1.2, §7.1.4 deviation):
         CreateEventEx accepts EventGroup GUID but ignores it.  Signaling
         an event in a group does NOT propagate to other group members.
         Not needed for fuzzing — no inter-driver group coordination.

      5. No EVT_RUNTIME support (§7.1.1 deviation):
         mEventTable[] does not include EVT_RUNTIME (0x40000000) combinations.
         Runtime services are out of scope for the host-based fuzzing model.

      6. Timer tick semantics (§7.1.7 deviation):
         Spec says TimerRelative with TriggerTime=0 fires "on next timer tick".
         Mock fires immediately via Fire-on-SetTimer or on next Advance call.

    Per-iteration reset:
    - MockEventResetState resets ALL event/timer state for a clean iteration:
      events, close listeners, simulated time, and the firing guard.

    Architecture:
    - Mock events are stored in a static array (gMockEvents)
    - Timer events have TriggerTime/Period set by SetTimer
    - Time is simulated via gSimulatedSystemTime (no real OS timers)
    - Fire-on-SetTimer ensures timer callbacks get exercised during fuzzing

    AFL Compatibility:
    - No signals (SIGALRM) used - won't conflict with AFL's timeout mechanism
    - No setitimer/alarm calls
    - All time is simulated in-process
    - Fully deterministic and reproducible

    Copyright (c) 2024, HBFAplus Contributors. All rights reserved.
    SPDX-License-Identifier: BSD-2-Clause-Patent
**/

#include <Uefi.h>
#include <Library/DebugLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/BaseLib.h>

#include "Event.h"
#include "MockFuzzContext.h"

//
// From Tpl.c — needed for the RaiseTpl/RestoreTpl pattern in
// CoreSignalEvent (mirrors real edk2's event lock acquire/release).
//
extern EFI_TPL  gEfiCurrentTpl;

EFI_TPL
EFIAPI
CoreRaiseTpl (
  IN EFI_TPL  NewTpl
  );

VOID
EFIAPI
CoreRestoreTpl (
  IN EFI_TPL  NewTpl
  );

//
// UEFI Spec §7.1.1 (CreateEvent) valid event type whitelist.
// From edk2 Core/Dxe/Event/Event.c mEventTable[].
// Spec: "The valid combinations that a Type parameter should have are:
//        EVT_TIMER, EVT_NOTIFY_WAIT, EVT_NOTIFY_SIGNAL,
//        EVT_SIGNAL_EXIT_BOOT_SERVICES, EVT_SIGNAL_VIRTUAL_ADDRESS_CHANGE,
//        and combinations of these." (see §7.1.1 Description)
// CoreCreateEvent rejects any Type not in this table.
//
// NOTE: EVT_RUNTIME (0x40000000) combinations are omitted — runtime
// services are out of scope for the host fuzzing environment.
//
STATIC CONST UINT32  mEventTable[] = {
  EVT_TIMER | EVT_NOTIFY_SIGNAL,           // 0x80000200
  EVT_TIMER,                               // 0x80000000
  EVT_NOTIFY_WAIT,                         // 0x00000100
  EVT_NOTIFY_SIGNAL,                       // 0x00000200
  EVT_SIGNAL_EXIT_BOOT_SERVICES,           // 0x00000201
  EVT_SIGNAL_VIRTUAL_ADDRESS_CHANGE,       // 0x60000202
  0x00000000,                              // Plain event
  EVT_TIMER | EVT_NOTIFY_WAIT,             // 0x80000100
};

//
// ============================================================================
// Global State - Events
// ============================================================================
//

//
// Static array of mock events. Using static array instead of dynamic allocation
// because: (1) avoids memory allocation during event creation which could fail,
// (2) simplifies iteration for timer firing,
// (3) 64 events * ~64 bytes = ~4KB which is negligible.
//
MOCK_EVENT  gMockEvents[MAX_MOCK_EVENTS];

//
// Number of events currently in use. Events are allocated linearly from the
// array and never freed back to it (CloseEvent just marks Signature = 0).
// This simplifies bookkeeping and is fine for fuzzing where we reset per-iteration.
//
UINTN  gMockEventCount = 0;

//
// Bitmask of TPL levels with pending event notifications.
// Bit N is set when at least one event with NotifyTpl == N has
// NotifyPending == TRUE.  Mirrors real edk2 gEventPending.
// Used by CoreRestoreTpl's dispatch loop for O(1) priority scanning.
//
UINTN  gEventPending = 0;

//
// ============================================================================
// Global State - Timer Simulation
// ============================================================================
//

//
// Simulated system time in 100-nanosecond units.
// This matches UEFI's native time unit (EFI_TIMER_PERIOD uses 100ns).
// Starting at 0 and incremented only by MockTimerAdvance calls.
//
STATIC UINT64  gSimulatedSystemTime = 0;

//
// Flag indicating if the timer system has been initialized.
// Used to catch calls before MockTimerInit.
//
STATIC BOOLEAN  gTimerInitialized = FALSE;

//
// ============================================================================
// Global State - Fire-on-SetTimer
// ============================================================================
//

//
// When TRUE, timer callbacks fire immediately when SetTimer() arms a timer.
// This ensures timer handler code gets exercised during fuzzing without
// requiring the harness to manually call MockTimerAdvance().
// Default: TRUE for maximum fuzzing coverage.
//
BOOLEAN  gMockTimerFireOnSetTimer = TRUE;

//
// Re-entrancy guard for fire-on-SetTimer.  When TRUE, CoreSetTimer will NOT
// call CoreSignalEvent even if gMockTimerFireOnSetTimer requests it.  This
// prevents infinite dispatch loops when a timer callback calls CoreSetTimer
// for another (or the same) event.
//
STATIC BOOLEAN  gFireOnSetTimerInProgress = FALSE;

//
// Global pump context used by CoreCloseEvent() to auto-unregister events.
// See Event.h for full documentation.
//
MOCK_FUZZ_CONTEXT  *gMockEventPumpContext = NULL;

//
// Re-entrancy guard to prevent infinite recursion if a timer callback
// calls SetTimer() on itself or another timer.
//
STATIC BOOLEAN  gFiringInProgress = FALSE;

//
// ============================================================================
// Internal Helper Functions
// ============================================================================
//

/**
  Set the global fuzz pump context for auto-registration.

  @param[in]  Ctx  Fuzz context to use as pump, or NULL to disable.
**/
VOID
EFIAPI
MockEventSetPumpContext (
  IN MOCK_FUZZ_CONTEXT  *Ctx
  )
{
  gMockEventPumpContext = Ctx;
  DEBUG ((DEBUG_VERBOSE, "MockEventSetPumpContext: Ctx=%p\n", Ctx));
}

//
// ============================================================================
// CloseEvent Listener Implementation
// ============================================================================
//

/**
  Check if an event handle is a valid mock event.

  Internal to EventHost.c — used by CoreSignalEvent, CoreCloseEvent,
  CoreSetTimer, CoreCheckEvent, CoreWaitForEvent for parameter validation.

  @param[in]  Event  Event handle to validate

  @retval  TRUE   Event is a valid mock event with correct signature
  @retval  FALSE  Event is NULL, not in our array, or has been closed
**/
STATIC
BOOLEAN
IsValidMockEvent (
  IN EFI_EVENT  Event
  )
{
  MOCK_EVENT  *MockEvent = (MOCK_EVENT *)Event;

  //
  // Check if pointer is within our event array bounds
  //
  if (MockEvent < &gMockEvents[0] || MockEvent >= &gMockEvents[MAX_MOCK_EVENTS]) {
    return FALSE;
  }

  //
  // Check signature is valid (not closed)
  //
  return (MockEvent->Signature == MOCK_EVENT_SIGNATURE);
}

/**
  Check and fire any timer events that have expired.

  UEFI Spec §7.1.7 (SetTimer) cross-reference:
    Spec defines three timer modes — TimerCancel, TimerPeriodic, TimerRelative.
    For TimerPeriodic: "The event is to be signaled periodically at
    TriggerTime intervals from the current time."
    For TimerRelative: "The event is to be signaled in TriggerTime
    100ns units."

  This function implements the timer tick engine that checks absolute
  deadlines against gSimulatedSystemTime.  For periodic timers it
  re-arms by advancing TriggerTime by Period (catch-up semantics:
  if a large time jump spans multiple periods, the timer fires once
  per Advance call until caught up, giving protocol code the correct
  invocation count).

  Iterates through all mock events, checking if any timer events have
  TriggerTime <= current simulated time. For expired timers:
  1. Invokes the notify function via MockEventSignal (§7.1.4 semantics)
  2. Re-arms periodic timers for the next interval
  3. Clears TriggerTime for one-shot timers

  This is the core timer-firing logic called by MockTimerAdvance.

  @return  None
**/
STATIC
VOID
FireExpiredTimers (
  VOID
  )
{
  UINTN       Index;
  MOCK_EVENT  *Event;

  //
  // Re-entrancy check - prevent recursive firing
  //
  if (gFiringInProgress) {
    return;
  }

  gFiringInProgress = TRUE;

  //
  // Iterate all events looking for armed timer events that have expired
  //
  for (Index = 0; Index < gMockEventCount; Index++) {
    Event = &gMockEvents[Index];

    //
    // Skip invalid events (closed or never created)
    //
    if (Event->Signature != MOCK_EVENT_SIGNATURE) {
      continue;
    }

    //
    // Skip non-timer events (no EVT_TIMER flag)
    //
    if ((Event->Type & EVT_TIMER) == 0) {
      continue;
    }

    //
    // Skip timers that aren't armed (TriggerTime == 0 means cancelled)
    //
    if (Event->TriggerTime == 0) {
      continue;
    }

    //
    // Check if this timer has expired
    // TriggerTime is an absolute time in 100ns units
    //
    if (gSimulatedSystemTime >= Event->TriggerTime) {
      DEBUG ((DEBUG_VERBOSE, "FireExpiredTimers: Timer event %p expired at time %lu\n",
              Event, gSimulatedSystemTime));

      //
      // Fire the timer by signaling its event.
      // Use MockEventSignal which respects UEFI spec:
      //   - EVT_NOTIFY_SIGNAL: invokes NotifyFunction immediately
      //   - EVT_NOTIFY_WAIT: only sets IsSignaled (callback deferred to CheckEvent/WaitForEvent)
      //   - Neither: only sets IsSignaled
      //
      MockEventSignal (Event);

      //
      // Handle periodic vs one-shot timers
      //
      if (Event->Period > 0) {
        //
        // Periodic timer: Re-arm for next interval.
        // If the time advance jumped past multiple periods (e.g. a single
        // MockTimerAdvance(10s) with a 200ms period), we catch-up by
        // re-arming to the earliest future deadline rather than skipping
        // straight to now + Period.  This ensures the timer fires on
        // every subsequent Advance until the backlog is cleared, giving
        // protocol code (e.g. TCP retransmit) the correct invocation count.
        //
        Event->TriggerTime += Event->Period;
        if (Event->TriggerTime <= gSimulatedSystemTime) {
          //
          // Still in the past — will fire again on next iteration
          // of the outer MockTimerAdvance100ns call's FireExpiredTimers.
          // This naturally catches up one period per Advance call.
          //
          DEBUG ((DEBUG_VERBOSE, "FireExpiredTimers: Periodic timer %p still behind, next=%lu\n",
                  Event, Event->TriggerTime));
        } else {
          DEBUG ((DEBUG_VERBOSE, "FireExpiredTimers: Re-armed periodic timer %p, next=%lu\n",
                  Event, Event->TriggerTime));
        }
      } else {
        //
        // One-shot timer: Disarm by setting TriggerTime to 0
        //
        Event->TriggerTime = 0;
        DEBUG ((DEBUG_VERBOSE, "FireExpiredTimers: One-shot timer %p complete, disarmed\n", Event));
      }
    }
  }

  gFiringInProgress = FALSE;
}

//
// ============================================================================
// Public API (called by MockTimerLib)
// ============================================================================
//

/**
  Queue a mock event for deferred notification dispatch.

  UEFI Spec §7.1.4 (SignalEvent) cross-reference:
    Spec: "If the event is of type EVT_NOTIFY_SIGNAL, then the event's
           notification function is scheduled to be invoked."

  This is the internal queue helper — mirrors real edk2 CoreNotifyEvent()
  (MdeModulePkg/Core/Dxe/Event/Event.c).  It sets the NotifyPending flag
  and the gEventPending bitmask bit for the event's NotifyTpl.

  Callbacks are NOT fired here.  Dispatch happens in CoreRestoreTpl()
  via MockDispatchEventNotifies(), matching real edk2's flow:
    CoreSignalEvent → CoreAcquireEventLock (RaiseTpl HIGH)
    → CoreNotifyEvent (queue)
    → CoreReleaseEventLock (RestoreTpl → dispatches pending events)

  Stack depth is bounded at 4 (one per TPL level), regardless of
  signal chain length, because events at the same or lower TPL are
  not dispatched recursively — they're picked up by the outer
  iterative dispatch loop in CoreRestoreTpl.

  §7.1.4 also says EVT_NOTIFY_WAIT callbacks are NOT invoked by
  SignalEvent; they fire only via CheckEvent (§7.1.6) or
  WaitForEvent (§7.1.5).  We comply with that.

  This is the internal implementation used when firing timer events.
  Accessible by MockTimerLib for timer firing.

  @param[in]  Event  The mock event to signal
**/
VOID
EFIAPI
MockEventSignal (
  IN MOCK_EVENT  *Event
  )
{
  if (Event == NULL || Event->Signature != MOCK_EVENT_SIGNATURE) {
    return;
  }

  //
  // Mark event as signaled (§7.1.4: signaled state is set)
  //
  Event->IsSignaled = TRUE;

  //
  // §7.1.4: Only EVT_NOTIFY_SIGNAL events have their callback queued
  // when signaled.  EVT_NOTIFY_WAIT callbacks are deferred until
  // CheckEvent (§7.1.6) or WaitForEvent (§7.1.5).
  //
  // Queue the event by setting NotifyPending and the gEventPending
  // bitmask.  Actual dispatch happens when CoreRestoreTpl() lowers
  // TPL — matching real edk2 CoreNotifyEvent() + CoreRestoreTpl().
  //
  if ((Event->Type & EVT_NOTIFY_SIGNAL) != 0 && Event->NotifyFunction != NULL) {
    Event->NotifyPending = TRUE;
    gEventPending |= (UINTN)(1 << Event->NotifyTpl);
    DEBUG ((DEBUG_VERBOSE, "MockEventSignal: Queued event %p at NotifyTpl=%u\n",
            Event, (UINT32)Event->NotifyTpl));
  }
}

/**
  Dispatch all pending EVT_NOTIFY_SIGNAL events at a specific TPL level.

  Mirrors real edk2 CoreDispatchEventNotifies() from
  MdeModulePkg/Core/Dxe/Event/Event.c.

  Walks the event array and fires callbacks for events that have
  NotifyPending == TRUE and NotifyTpl == Priority.  Loops until no
  more pending events exist at this level — callbacks may signal
  additional events at the same TPL, which are picked up iteratively
  in the do/while loop (not recursively).

  Key invariant: gEfiCurrentTpl == Priority when this runs.  Callbacks
  execute at their event's NotifyTpl, matching real edk2 semantics.
  If a callback calls CoreSignalEvent, it raises to HIGH, queues the
  event, and restores to Priority.  That RestoreTpl dispatches events
  at TPL > Priority (higher levels) but NOT at Priority or below —
  preventing recursive dispatch at the same level.  Those same-level
  events accumulate and are processed by our do/while rescan.

  After draining, clears the gEventPending bit for this TPL level.

  @param[in]  Priority  The TPL level to dispatch.
**/
VOID
EFIAPI
MockDispatchEventNotifies (
  IN EFI_TPL  Priority
  )
{
  UINTN       Index;
  MOCK_EVENT  *Event;
  BOOLEAN     MoreWork;

  //
  // Loop until no more pending notifications at this TPL level.
  // A dispatched callback may signal more events at the same level —
  // they accumulate via MockEventSignal (sets NotifyPending + gEventPending)
  // and are picked up in the next iteration of this do/while loop.
  //
  // Max-iterations guard: prevents infinite looping when a callback
  // re-signals an event at the same TPL (e.g., fire-on-SetTimer for a
  // periodic timer whose callback re-arms itself).  Real edk2 doesn't
  // have this problem because SetTimer only arms — the ISR fires later.
  // 64 iterations is generous for any legitimate dispatch chain.
  //
  UINTN  Iterations = 0;
  #define DISPATCH_MAX_ITERATIONS  64

  do {
    MoreWork = FALSE;

    if (++Iterations > DISPATCH_MAX_ITERATIONS) {
      DEBUG ((DEBUG_WARN, "MockDispatchEventNotifies: Hit max iterations (%u) at TPL %u — breaking to avoid infinite loop\n",
              (UINT32)DISPATCH_MAX_ITERATIONS, (UINT32)Priority));
      break;
    }

    for (Index = 0; Index < gMockEventCount; Index++) {
      Event = &gMockEvents[Index];

      if (Event->Signature != MOCK_EVENT_SIGNATURE) {
        continue;
      }

      if (!Event->NotifyPending) {
        continue;
      }

      if (Event->NotifyTpl != Priority) {
        continue;
      }

      if (Event->NotifyFunction == NULL) {
        Event->NotifyPending = FALSE;
        continue;
      }

      //
      // Clear pending BEFORE dispatch to avoid re-fire if the
      // callback signals the same event again (matches real edk2
      // which removes from queue before invoking callback).
      //
      Event->NotifyPending = FALSE;
      MoreWork = TRUE;

      DEBUG ((DEBUG_VERBOSE, "MockDispatchEventNotifies: Firing event %p (slot %u) at TPL %u\n",
              Event, (UINT32)Index, (UINT32)Priority));

      Event->NotifyFunction ((EFI_EVENT)Event, Event->NotifyContext);
    }
  } while (MoreWork);

  //
  // All pending events at this TPL have been dispatched.
  // Clear the pending bit.
  //
  gEventPending &= ~(UINTN)(1 << Priority);
}

/**
  Reset ALL event and timer state for a new fuzz iteration.

  This is the single per-iteration reset entry point.  It clears:
    1. Every allocated mock event (Signature, callbacks, timer fields)
    2. The event slot counter (gMockEventCount → 0)
    3. All close-event listeners (modules re-register each iteration)
    4. Simulated system time (gSimulatedSystemTime → 0)
    5. The re-entrancy firing guard (gFiringInProgress → FALSE)

  Call this at the top of each fuzz iteration — before loading new fuzz
  bytes and before calling the target driver.

  NOTE: MockTimerInit() is intentionally NOT re-called here.  Init is
  one-time setup (marks the timer subsystem as active and registers the
  TimerAdvanceFn callback on the pool).  Per-iteration cleanup belongs
  here, not in init.
**/
VOID
EFIAPI
MockEventResetState (
  VOID
  )
{
  UINTN  Index;

  //
  // 1. Clear all event slots.
  //
  for (Index = 0; Index < gMockEventCount; Index++) {
    gMockEvents[Index].Signature = 0;
    gMockEvents[Index].IsSignaled = FALSE;
    gMockEvents[Index].NotifyFunction = NULL;
    gMockEvents[Index].NotifyContext = NULL;
    gMockEvents[Index].TriggerTime = 0;
    gMockEvents[Index].Period = 0;
    gMockEvents[Index].Type = 0;
  }

  DEBUG ((DEBUG_VERBOSE, "MockEventResetState: Reclaimed %d event slot(s)\n", gMockEventCount));
  gMockEventCount = 0;

  //
  // 1b. Clear the event pending bitmask.
  //
  gEventPending = 0;

  //
  // 2. Reset simulated system time so every iteration starts at t=0.
  //
  gSimulatedSystemTime = 0;

  //
  // 3. Restore TPL to TPL_APPLICATION.  If a previous iteration aborted
  //    while TPL was elevated (e.g. crash inside RaiseTPL/RestoreTPL
  //    bracket), WaitForEvent and other TPL_APPLICATION-only services
  //    would fail on the next iteration without this reset.
  //
  gEfiCurrentTpl = TPL_APPLICATION;

  //
  // 4. Clear the re-entrancy guards in case a previous iteration aborted
  //    mid-fire (e.g. fuzzer-triggered ASSERT inside a timer callback).
  //
  gFiringInProgress         = FALSE;
  gFireOnSetTimerInProgress = FALSE;

  //
  // 5. Reset the auto-pump re-entrancy guard and restore auto-pump to
  //    its default enabled state in case the previous iteration changed it.
  //
  MockTplResetAutoPumpState ();

  DEBUG ((DEBUG_VERBOSE, "MockEventResetState: All event/timer state reset (TPL restored)\n"));
}

//
// ============================================================================
// Timer Simulation Public API
// ============================================================================
//

/**
  Initialize the mock timer service (one-time setup).

  Marks the timer subsystem as active and registers MockTimerAdvance as
  the pump timer callback so MockFuzzContextPumpEvents() can advance
  simulated time and fire expired timer events automatically.

  This is idempotent — safe to call more than once, but only needs to
  be called once before the AFL forkserver starts.

  NOTE: Does NOT reset simulated time.  Per-iteration time reset is
  handled by MockEventResetState(), which is the single per-iteration
  reset entry point for all event and timer state.

  @return  None
**/
VOID
EFIAPI
MockTimerInit (
  VOID
  )
{
  MOCK_FUZZ_CONTEXT  *Pool;

  DEBUG ((DEBUG_INFO, "MockTimerInit: Initializing deterministic timer service\n"));

  gTimerInitialized = TRUE;

  //
  // Register MockTimerAdvance as the pump timer callback so that
  // MockFuzzContextPumpEvents() automatically advances simulated time
  // and fires expired timer events (TCP heartbeat, etc.).
  //
  Pool = MockFuzzContextGetPool ();
  Pool->TimerAdvanceFn = MockTimerAdvance;

  DEBUG ((DEBUG_INFO, "MockTimerInit: Registered TimerAdvanceFn, timer active\n"));
}

//
// MockTimerReset was removed in the event/timer cleanup.
// Per-iteration reset of ALL state (events, time, close listeners,
// firing guard) is now handled by the single entry point:
//
//   MockEventResetState()
//
// See the comment above MockEventResetState for details.
//

/**
  Advance simulated time by the specified number of microseconds.

  This is the main API for harnesses to use. It:
  1. Converts microseconds to 100ns units
  2. Increments simulated system time
  3. Fires any timer events that have expired

  Example:
    // Advance 100ms of simulated time
    MockTimerAdvance(100000);

    // Advance 1 second
    MockTimerAdvance(1000000);

  @param[in]  Microseconds  Time to advance in microseconds

  @return  None
**/
VOID
EFIAPI
MockTimerAdvance (
  IN UINT64  Microseconds
  )
{
  UINT64  Time100ns;

  if (!gTimerInitialized) {
    DEBUG ((DEBUG_WARN, "MockTimerAdvance: Timer not initialized, call MockTimerInit first\n"));
    return;
  }

  //
  // Convert microseconds to 100ns units
  // 1 microsecond = 10 * 100ns
  //
  Time100ns = Microseconds * 10;

  //
  // Call the lower-level advance function
  //
  MockTimerAdvance100ns (Time100ns);
}

/**
  Advance simulated time by the specified number of 100-nanosecond units.

  Lower-level API for fine-grained time control. Most harnesses should use
  MockTimerAdvance(microseconds) instead.

  @param[in]  Time100ns  Time to advance in 100ns units

  @return  None
**/
VOID
EFIAPI
MockTimerAdvance100ns (
  IN UINT64  Time100ns
  )
{
  UINT64   OldTime;
  EFI_TPL  OriginalTpl;

  if (!gTimerInitialized) {
    DEBUG ((DEBUG_WARN, "MockTimerAdvance100ns: Timer not initialized\n"));
    return;
  }

  //
  // Record old time for debug logging
  //
  OldTime = gSimulatedSystemTime;

  //
  // Advance simulated system time
  //
  gSimulatedSystemTime += Time100ns;

  DEBUG ((DEBUG_VERBOSE, "MockTimerAdvance100ns: Time %lu -> %lu (+%lu)\n",
          OldTime, gSimulatedSystemTime, Time100ns));

  //
  // Simulate timer interrupt: raise to HIGH, scan for expired timers
  // (which queues events via MockEventSignal), then restore TPL.
  // The RestoreTpl dispatches the queued events at their proper TPL
  // levels — matching real edk2 where timer ISR queues events and
  // CoreRestoreTpl dispatches them when TPL drops.
  //
  OriginalTpl = CoreRaiseTpl (TPL_HIGH_LEVEL);
  FireExpiredTimers ();
  CoreRestoreTpl (OriginalTpl);
}

/**
  Get the current simulated system time.

  @return  Current simulated time in 100ns units
**/
UINT64
EFIAPI
MockTimerGetSystemTime (
  VOID
  )
{
  return gSimulatedSystemTime;
}

//
// ============================================================================
// Boot Services Event Implementations
// ============================================================================
//

/**
  Creates a new event.

  UEFI Spec §7.1.1 (CreateEvent):
    - Type must be a valid combination from the whitelist (mEventTable[]).
    - EVT_NOTIFY_WAIT and EVT_NOTIFY_SIGNAL are mutually exclusive.
    - If Type includes EVT_NOTIFY_WAIT or EVT_NOTIFY_SIGNAL, then
      NotifyFunction must be non-NULL and NotifyTpl must be a valid
      level (TPL_CALLBACK..TPL_NOTIFY, i.e. > TPL_APPLICATION and
      < TPL_HIGH_LEVEL).
    - Returns EFI_INVALID_PARAMETER for unsupported Type bits, both
      WAIT+SIGNAL, NULL NotifyFunction with notify type, invalid TPL.
    - Allowed TPL: < TPL_HIGH_LEVEL (see §7.1 TPL Usage table).

  Mock compliance:
    - Type whitelist check: COMPLIANT (mEventTable[]).
    - WAIT/SIGNAL exclusivity: COMPLIANT (implied by whitelist — no
      entry has both EVT_NOTIFY_WAIT | EVT_NOTIFY_SIGNAL).
    - NotifyFunction/NotifyTpl validation: COMPLIANT.
    - Slot-based allocation: deviation — spec uses dynamic allocation;
      mock uses a fixed-size array (MAX_MOCK_EVENTS) sufficient for
      fuzzing.

  @param[in]   Type           Event type (EVT_TIMER, EVT_NOTIFY_SIGNAL, etc.)
  @param[in]   NotifyTpl      TPL at which to call NotifyFunction
  @param[in]   NotifyFunction Optional callback when event is signaled
  @param[in]   NotifyContext  Context passed to NotifyFunction
  @param[out]  Event          Receives the new event handle

  @retval  EFI_SUCCESS           Event created successfully
  @retval  EFI_OUT_OF_RESOURCES  No more event slots available
  @retval  EFI_INVALID_PARAMETER Event output pointer is NULL, invalid Type,
                                 or missing NotifyFunction for notify type
**/
EFI_STATUS
EFIAPI
CoreCreateEvent (
  IN  UINT32            Type,
  IN  EFI_TPL           NotifyTpl,
  IN  EFI_EVENT_NOTIFY  NotifyFunction  OPTIONAL,
  IN  VOID              *NotifyContext  OPTIONAL,
  OUT EFI_EVENT         *Event
  )
{
  MOCK_EVENT  *NewEvent;

  //
  // Validate output parameter
  //
  if (Event == NULL) {
    DEBUG ((DEBUG_ERROR, "CoreCreateEvent: Event output pointer is NULL\n"));
    return EFI_INVALID_PARAMETER;
  }

  //
  // §7.1.1: Only allow event types from the whitelist.
  // This catches garbage type bits and invalid combinations like
  // EVT_RUNTIME alone or EVT_NOTIFY_WAIT | EVT_NOTIFY_SIGNAL.
  //
  {
    UINTN    TypeIdx;
    BOOLEAN  TypeValid;

    TypeValid = FALSE;
    for (TypeIdx = 0; TypeIdx < sizeof (mEventTable) / sizeof (mEventTable[0]); TypeIdx++) {
      if (Type == mEventTable[TypeIdx]) {
        TypeValid = TRUE;
        break;
      }
    }

    if (!TypeValid) {
      DEBUG ((DEBUG_ERROR, "CoreCreateEvent: Invalid event type 0x%x\n", Type));
      return EFI_INVALID_PARAMETER;
    }
  }

  //
  // §7.1.1: EVT_NOTIFY_SIGNAL and EVT_NOTIFY_WAIT require a non-NULL
  // NotifyFunction and a valid NotifyTpl (> TPL_APPLICATION, < TPL_HIGH_LEVEL).
  // edk2 CoreCreateEventInternal enforces the same.
  //
  if ((Type & (EVT_NOTIFY_WAIT | EVT_NOTIFY_SIGNAL)) != 0) {
    if (NotifyFunction == NULL) {
      DEBUG ((DEBUG_ERROR, "CoreCreateEvent: Notify event type 0x%x requires NotifyFunction\n", Type));
      return EFI_INVALID_PARAMETER;
    }

    if ((NotifyTpl <= TPL_APPLICATION) || (NotifyTpl >= TPL_HIGH_LEVEL)) {
      DEBUG ((DEBUG_ERROR, "CoreCreateEvent: Invalid NotifyTpl %d for notify event\n", (int)NotifyTpl));
      return EFI_INVALID_PARAMETER;
    }
  } else {
    //
    // Non-notify event: per edk2 CoreCreateEventInternal, zero out the
    // notify fields so accidentally-passed callbacks cannot fire.
    //
    NotifyTpl      = 0;
    NotifyFunction = NULL;
    NotifyContext  = NULL;
  }

  //
  // Try to reuse a closed slot first (Signature == 0 means closed/free)
  //
  NewEvent = NULL;
  for (UINTN Index = 0; Index < gMockEventCount; Index++) {
    if (gMockEvents[Index].Signature == 0) {
      NewEvent = &gMockEvents[Index];
      break;
    }
  }

  //
  // If no reusable slot found, allocate next slot from the array
  //
  if (NewEvent == NULL) {
    if (gMockEventCount >= MAX_MOCK_EVENTS) {
      DEBUG ((DEBUG_ERROR, "CoreCreateEvent: Out of event slots (max=%d)\n", MAX_MOCK_EVENTS));
      return EFI_OUT_OF_RESOURCES;
    }
    NewEvent = &gMockEvents[gMockEventCount];
    gMockEventCount++;
  }

  //
  // Initialize the event structure
  //
  NewEvent->Signature      = MOCK_EVENT_SIGNATURE;
  NewEvent->Type           = Type;
  NewEvent->NotifyTpl      = NotifyTpl;
  NewEvent->NotifyFunction = NotifyFunction;
  NewEvent->NotifyContext  = NotifyContext;
  NewEvent->TriggerTime    = 0;       // Not armed until SetTimer called
  NewEvent->Period         = 0;       // One-shot by default
  NewEvent->IsSignaled     = FALSE;

  DEBUG ((DEBUG_VERBOSE, "CoreCreateEvent: Created event %p (slot %d), Type=0x%x\n",
          NewEvent, gMockEventCount - 1, Type));

  *Event = (EFI_EVENT)NewEvent;

  //
  // NOTE: We intentionally do NOT auto-register events with the pump here.
  //
  // In real UEFI, events fire only when:
  //   1. Timer mechanism fires them  (handled by MockTimerAdvance / FireExpiredTimers)
  //   2. A protocol driver completes I/O and signals the token event
  //   3. edk2 code itself calls gBS->SignalEvent()
  //
  // Auto-registering every callback event with the pump violates UEFI
  // semantics: it causes token events (e.g. IpIo DummyRcvToken) to fire
  // before Receive() has been called, leading to NULL-pointer ASSERTs in
  // edk2 code that rightfully expects the token to be populated first.
  //
  // Mock protocols already explicitly call MockFuzzContextRegisterPumpEvent()
  // in their Receive/Transmit paths, so all legitimate async operations are
  // still driven by the fuzzer.
  //

  return EFI_SUCCESS;
}

/**
  Creates a new event with event group support.

  UEFI Spec §7.1.2 (CreateEventEx):
    - Same Type restrictions as CreateEvent (§7.1.1) EXCEPT:
      EVT_SIGNAL_EXIT_BOOT_SERVICES and EVT_SIGNAL_VIRTUAL_ADDRESS_CHANGE
      are NOT valid ("must NOT be combined with CreateEventEx").
    - EventGroup: If non-NULL, all events in the same group are signaled
      together when any one member is signaled.
    - Type may be 0 if EventGroup is specified.

  Mock compliance:
    - Type validation: delegates to CoreCreateEvent (§7.1.1 whitelist).
      This is slightly permissive — spec says EXIT_BOOT_SERVICES and
      VIRTUAL_ADDRESS_CHANGE should be rejected for CreateEventEx, but
      the mock allows them.  Acceptable for fuzzing.
    - EventGroup: ACCEPTED but IGNORED.  No group-signal propagation.
      (Not needed for fuzzing — no inter-driver group coordination.)

  @param[in]   Type           Event type
  @param[in]   NotifyTpl      TPL for notification
  @param[in]   NotifyFunction Callback function
  @param[in]   NotifyContext  Callback context
  @param[in]   EventGroup     Event group GUID (accepted but ignored in mock)
  @param[out]  Event          New event handle

  @retval  EFI_SUCCESS  Event created
  @retval  Others       Error from CoreCreateEvent
**/
EFI_STATUS
EFIAPI
CoreCreateEventEx (
  IN       UINT32            Type,
  IN       EFI_TPL           NotifyTpl,
  IN       EFI_EVENT_NOTIFY  NotifyFunction  OPTIONAL,
  IN CONST VOID              *NotifyContext  OPTIONAL,
  IN CONST EFI_GUID          *EventGroup     OPTIONAL,
  OUT      EFI_EVENT         *Event
  )
{
  //
  // For fuzzing, we don't need event group functionality.
  // Just create a regular event. Cast away const for internal storage.
  //
  DEBUG ((DEBUG_VERBOSE, "CoreCreateEventEx: EventGroup ignored in mock\n"));
  return CoreCreateEvent (Type, NotifyTpl, NotifyFunction, (VOID *)NotifyContext, Event);
}

/**
  Sets the type of timer and trigger time for a timer event.

  UEFI Spec §7.1.7 (SetTimer):
    - Event must have been created with EVT_TIMER type.
    - TimerCancel: "Cancels any outstanding timer request for the event."
    - TimerPeriodic: "The event is to be signaled periodically at
      TriggerTime intervals from the current time.  If TriggerTime is
      0 then the timer event will be signaled on every timer tick."
    - TimerRelative: "The event is to be signaled in TriggerTime 100ns
      units.  If TriggerTime is 0 it will be signaled on the next timer
      tick."
    - Allowed TPL: < TPL_HIGH_LEVEL.

  Mock compliance:
    - EVT_TIMER check: COMPLIANT.
    - TimerCancel: COMPLIANT (clears TriggerTime and Period).
    - TimerPeriodic: COMPLIANT (stores absolute deadline, re-arms).
    - TimerRelative: COMPLIANT (stores absolute deadline, disarms after fire).
    - TriggerTime=0 handling: Spec says "every timer tick" / "next tick".
      Mock clamps to 1 (100ns) to prevent zero-period runaway, then fires
      via Fire-on-SetTimer or next MockTimerAdvance.
    - Fire-on-SetTimer: DEVIATION — fires callback immediately on SetTimer
      call for fuzzing coverage, rather than waiting for timer tick.

  @param[in]  Event        Timer event to configure
  @param[in]  Type         Timer mode (Cancel/Periodic/Relative)
  @param[in]  TriggerTime  Time in 100ns units

  @retval  EFI_SUCCESS           Timer configured
  @retval  EFI_INVALID_PARAMETER Invalid event handle or not a timer event
**/
EFI_STATUS
EFIAPI
CoreSetTimer (
  IN EFI_EVENT        Event,
  IN EFI_TIMER_DELAY  Type,
  IN UINT64           TriggerTime
  )
{
  MOCK_EVENT  *MockEvent = (MOCK_EVENT *)Event;

  //
  // Validate the event handle
  //
  if (!IsValidMockEvent (Event)) {
    DEBUG ((DEBUG_ERROR, "CoreSetTimer: Invalid event handle %p\n", Event));
    return EFI_INVALID_PARAMETER;
  }

  //
  // Verify this is a timer event (has EVT_TIMER flag set)
  //
  if ((MockEvent->Type & EVT_TIMER) == 0) {
    DEBUG ((DEBUG_ERROR, "CoreSetTimer: Event %p is not a timer event\n", Event));
    return EFI_INVALID_PARAMETER;
  }

  //
  // Configure timer based on requested mode
  //
  switch (Type) {
    case TimerCancel:
      //
      // Disarm the timer - it will not fire
      //
      MockEvent->TriggerTime = 0;
      MockEvent->Period      = 0;
      DEBUG ((DEBUG_VERBOSE, "CoreSetTimer: Event %p cancelled\n", Event));
      break;

    case TimerPeriodic:
      //
      // §7.1.7: Periodic timer — fires repeatedly at TriggerTime intervals.
      // Store as absolute deadline (current time + delay) for consistency
      // with FireExpiredTimers which compares against gSimulatedSystemTime.
      //
      // §7.1.7: "If TriggerTime is 0, then the timer event will be
      // signaled on every timer tick."  We use a minimum of 1 tick
      // (100ns) to prevent zero-period runaway in the mock.
      //
      if (TriggerTime == 0) {
        TriggerTime = 1;
      }

      MockEvent->TriggerTime = gSimulatedSystemTime + TriggerTime;
      MockEvent->Period      = TriggerTime;
      DEBUG ((DEBUG_VERBOSE, "CoreSetTimer: Event %p periodic, period=%lu00ns, trigger=%lu\n",
              Event, TriggerTime, MockEvent->TriggerTime));

      //
      // Fire-on-SetTimer: DEVIATION from spec — immediately signal the
      // event for fuzzing coverage.  Spec would wait until the next
      // timer tick (§7.1.7).  Uses CoreSignalEvent which queues the
      // event and dispatches via RaiseTpl/RestoreTpl.
      //
      // The gFiringInProgress guard prevents double-firing when called
      // from within FireExpiredTimers (which already queued this event).
      // The gFireOnSetTimerInProgress guard prevents infinite recursion
      // when a timer callback calls CoreSetTimer on another event.
      //
      if (gMockTimerFireOnSetTimer && !gFiringInProgress && !gFireOnSetTimerInProgress) {
        gFireOnSetTimerInProgress = TRUE;
        CoreSignalEvent ((EFI_EVENT)MockEvent);
        gFireOnSetTimerInProgress = FALSE;
      }
      break;

    case TimerRelative:
      //
      // §7.1.7: One-shot timer — fires once after TriggerTime delay.
      // "The event is to be signaled in TriggerTime 100ns units."
      // Store as absolute deadline (current time + delay).
      //
      MockEvent->TriggerTime = gSimulatedSystemTime + TriggerTime;
      MockEvent->Period      = 0;            // One-shot, no repeat
      DEBUG ((DEBUG_VERBOSE, "CoreSetTimer: Event %p relative, delay=%lu00ns, trigger=%lu\n",
              Event, TriggerTime, MockEvent->TriggerTime));

      //
      // Fire-on-SetTimer: DEVIATION from spec — immediately signal the
      // event for fuzzing coverage.  Spec would wait until the next
      // timer tick (§7.1.7).  Uses CoreSignalEvent which queues
      // and dispatches via RaiseTpl/RestoreTpl.
      //
      // gFireOnSetTimerInProgress prevents recursive fire-on-SetTimer
      // when a timer callback calls CoreSetTimer on another event.
      //
      if (gMockTimerFireOnSetTimer && !gFiringInProgress && !gFireOnSetTimerInProgress) {
        gFireOnSetTimerInProgress = TRUE;
        CoreSignalEvent ((EFI_EVENT)MockEvent);
        gFireOnSetTimerInProgress = FALSE;
        //
        // For one-shot, disarm after firing
        //
        MockEvent->TriggerTime = 0;
      }
      break;

    default:
      DEBUG ((DEBUG_ERROR, "CoreSetTimer: Invalid timer type %d\n", Type));
      return EFI_INVALID_PARAMETER;
  }

  return EFI_SUCCESS;
}

/**
  Stops execution until an event is signaled.

  UEFI Spec §7.1.5 (WaitForEvent):
    - MUST be called at TPL_APPLICATION; returns EFI_UNSUPPORTED otherwise.
    - If any event has EVT_NOTIFY_SIGNAL type, return EFI_INVALID_PARAMETER.
    - For each unsignaled event with EVT_NOTIFY_WAIT, invoke its
      NotifyFunction to give it a chance to signal itself.
    - Blocks until at least one event is signaled, then returns its index.
    - Clears the signaled state of the returned event.

  Mock compliance:
    - TPL check: COMPLIANT.
    - NOTIFY_SIGNAL rejection: COMPLIANT.
    - NOTIFY_WAIT callback invocation: COMPLIANT.
    - Blocking: DEVIATION — spec says this blocks.  Mock does ONE pass
      (no blocking loop) and returns the first signaled event, or
      Index=0 if none signaled.  This prevents infinite hangs in fuzzing.

  @param[in]   NumberOfEvents  Number of events to wait on
  @param[in]   Event           Array of events
  @param[out]  Index           Index of signaled event

  @retval  EFI_SUCCESS            An event was signaled
  @retval  EFI_UNSUPPORTED        Current TPL is not TPL_APPLICATION
  @retval  EFI_INVALID_PARAMETER  An event has EVT_NOTIFY_SIGNAL type, or
                                  NumberOfEvents is 0, or Event/Index is NULL
**/
EFI_STATUS
EFIAPI
CoreWaitForEvent (
  IN  UINTN      NumberOfEvents,
  IN  EFI_EVENT  *Event,
  OUT UINTN      *Index
  )
{
  UINTN       Idx;
  MOCK_EVENT  *MockEvent;

  //
  // §7.1.5: WaitForEvent can only be called at TPL_APPLICATION
  //
  if (gEfiCurrentTpl != TPL_APPLICATION) {
    DEBUG ((DEBUG_ERROR, "CoreWaitForEvent: Called at TPL %d, requires TPL_APPLICATION\n",
            (int)gEfiCurrentTpl));
    return EFI_UNSUPPORTED;
  }

  //
  // Basic parameter validation
  //
  if (NumberOfEvents == 0 || Event == NULL || Index == NULL) {
    return EFI_INVALID_PARAMETER;
  }

  //
  // §7.1.5: If any event in the array has EVT_NOTIFY_SIGNAL, reject
  //
  for (Idx = 0; Idx < NumberOfEvents; Idx++) {
    MockEvent = (MOCK_EVENT *)Event[Idx];
    if (IsValidMockEvent (Event[Idx]) && (MockEvent->Type & EVT_NOTIFY_SIGNAL) != 0) {
      DEBUG ((DEBUG_ERROR, "CoreWaitForEvent: Event[%d] has EVT_NOTIFY_SIGNAL\n", (int)Idx));
      return EFI_INVALID_PARAMETER;
    }
  }

  //
  // §7.1.5: For each unsignaled EVT_NOTIFY_WAIT event, invoke its
  // callback ("the mechanism that makes the event become signaled").
  // Mock does ONE pass (no blocking loop) for fuzzing.
  //
  for (Idx = 0; Idx < NumberOfEvents; Idx++) {
    MockEvent = (MOCK_EVENT *)Event[Idx];
    if (!IsValidMockEvent (Event[Idx])) {
      continue;
    }
    if (!MockEvent->IsSignaled &&
        (MockEvent->Type & EVT_NOTIFY_WAIT) != 0 &&
        MockEvent->NotifyFunction != NULL)
    {
      MockEvent->NotifyFunction (Event[Idx], MockEvent->NotifyContext);
    }
  }

  //
  // Find first signaled event
  //
  for (Idx = 0; Idx < NumberOfEvents; Idx++) {
    MockEvent = (MOCK_EVENT *)Event[Idx];
    if (IsValidMockEvent (Event[Idx]) && MockEvent->IsSignaled) {
      MockEvent->IsSignaled = FALSE;
      *Index = Idx;
      return EFI_SUCCESS;
    }
  }

  //
  // None signaled — for fuzzing, return first event to avoid blocking
  //
  DEBUG ((DEBUG_VERBOSE, "CoreWaitForEvent: No event signaled, returning Index=0 (mock)\n"));
  *Index = 0;
  return EFI_SUCCESS;
}

/**
  Signals an event.

  UEFI Spec §7.1.4 (SignalEvent):
    - "If the event is already in the signaled state, no action is
      needed and EFI_SUCCESS is returned."
    - "If the event is of type EVT_NOTIFY_SIGNAL, then the event's
      notification function is scheduled to be invoked."
    - Allowed TPL: <= TPL_HIGH_LEVEL.

  Mock compliance — now matches real edk2 flow:
    Real edk2 CoreSignalEvent() does:
      AcquireEventLock (RaiseTpl HIGH) → CoreNotifyEvent (queue) →
      ReleaseEventLock (RestoreTpl Original → dispatches pending events)

    Our implementation mirrors this:
      RaiseTpl(HIGH) → MockEventSignal (queue) → RestoreTpl(Original)

    The RestoreTpl dispatches pending events at TPL levels > Original,
    matching real edk2's event dispatch semantics.  Stack depth is
    bounded at 4 (one per TPL level) because events at the same or
    lower TPL are queued and processed iteratively by the outer
    dispatch loop — never recursively.

  @param[in]  Event  Event to signal

  @retval  EFI_SUCCESS           Event signaled
  @retval  EFI_INVALID_PARAMETER Invalid event handle
**/
EFI_STATUS
EFIAPI
CoreSignalEvent (
  IN EFI_EVENT  Event
  )
{
  MOCK_EVENT  *MockEvent = (MOCK_EVENT *)Event;
  EFI_TPL     OriginalTpl;

  if (!IsValidMockEvent (Event)) {
    DEBUG ((DEBUG_ERROR, "CoreSignalEvent: Invalid event %p\n", Event));
    return EFI_INVALID_PARAMETER;
  }

  //
  // Mirror real edk2: acquire event lock (raise to HIGH), queue the
  // event, release lock (restore TPL → dispatches pending events).
  //
  // This ensures:
  // 1. The event is queued atomically (at HIGH, nothing else runs)
  // 2. Dispatch happens during RestoreTpl at the proper TPL level
  // 3. Stack depth is bounded by TPL hierarchy (4 levels max)
  //
  OriginalTpl = CoreRaiseTpl (TPL_HIGH_LEVEL);
  MockEventSignal (MockEvent);
  CoreRestoreTpl (OriginalTpl);

  return EFI_SUCCESS;
}

/**
  Closes an event.

  UEFI Spec §7.1.3 (CloseEvent):
    - "Closes an event and frees the event structure."
    - "If the event is a member of an event group, it is removed."
    - "It is safe to call this function within the corresponding
      notification function."
    - "If Event was registered with RegisterProtocolNotify(), then
      the corresponding registration will be removed."
    - Allowed TPL: < TPL_HIGH_LEVEL.

  Mock compliance:
    - Frees event: COMPLIANT (marks Signature=0, clears all fields).
    - Event group removal: N/A (no group propagation in mock).
    - Safe from notify: COMPLIANT (works from any context).
    - RegisterProtocolNotify: N/A (handled separately by Handle.c).

  @param[in]  Event  Event to close

  @retval  EFI_SUCCESS           Event closed
  @retval  EFI_INVALID_PARAMETER Invalid event handle
**/
EFI_STATUS
EFIAPI
CoreCloseEvent (
  IN EFI_EVENT  Event
  )
{
  MOCK_EVENT  *MockEvent = (MOCK_EVENT *)Event;

  //
  // Validate the event handle
  //
  if (!IsValidMockEvent (Event)) {
    DEBUG ((DEBUG_WARN, "CoreCloseEvent: Invalid or already closed event %p\n", Event));
    return EFI_INVALID_PARAMETER;
  }

  //
  // Auto-unregister from the pump if one is active
  //
  if (gMockEventPumpContext != NULL) {
    MockFuzzContextUnregisterPumpEvent (gMockEventPumpContext, Event);
  }

  //
  // §7.1.3: Cancel any pending timer and clear all fields.  Zero
  // everything for hygiene so stale data doesn't leak if slot is reused.
  //
  MockEvent->TriggerTime    = 0;
  MockEvent->Period         = 0;
  MockEvent->IsSignaled     = FALSE;
  MockEvent->NotifyFunction = NULL;
  MockEvent->NotifyContext  = NULL;
  MockEvent->Type           = 0;
  MockEvent->Signature      = 0;
  DEBUG ((DEBUG_VERBOSE, "CoreCloseEvent: Event %p closed and cleaned\n", Event));

  return EFI_SUCCESS;
}

/**
  Checks whether an event is in the signaled state.

  UEFI Spec §7.1.6 (CheckEvent):
    - "If Event is of type EVT_NOTIFY_SIGNAL, then EFI_INVALID_PARAMETER
      is returned."
    - If signaled: clears signaled state and returns EFI_SUCCESS.
    - If not signaled and EVT_NOTIFY_WAIT: queues notification function,
      then rechecks.  If still not signaled, returns EFI_NOT_READY.
    - If not signaled and no NOTIFY_WAIT: returns EFI_NOT_READY.
    - Allowed TPL: < TPL_HIGH_LEVEL.

  Mock compliance:
    - NOTIFY_SIGNAL rejection: COMPLIANT.
    - Signaled → clear + SUCCESS: COMPLIANT.
    - NOTIFY_WAIT callback invocation: COMPLIANT (fires inline).
    - TPL check: NOT ENFORCED (acceptable for fuzzing).

  @param[in]  Event  Event to check

  @retval  EFI_SUCCESS            Event is in the signaled state
  @retval  EFI_NOT_READY          Event is not signaled
  @retval  EFI_INVALID_PARAMETER  Invalid event handle, or event has
                                  EVT_NOTIFY_SIGNAL type (§7.1.6)
**/
EFI_STATUS
EFIAPI
CoreCheckEvent (
  IN EFI_EVENT  Event
  )
{
  MOCK_EVENT  *MockEvent = (MOCK_EVENT *)Event;

  if (!IsValidMockEvent (Event)) {
    return EFI_INVALID_PARAMETER;
  }

  //
  // §7.1.6: CheckEvent on an EVT_NOTIFY_SIGNAL event returns
  // EFI_INVALID_PARAMETER.  Signal-type events are driven by
  // SignalEvent (§7.1.4), not polled.
  //
  if ((MockEvent->Type & EVT_NOTIFY_SIGNAL) != 0) {
    return EFI_INVALID_PARAMETER;
  }

  //
  // §7.1.6: If the event has EVT_NOTIFY_WAIT and is not yet signaled,
  // invoke the notify function.  This is the mechanism that allows the
  // event's owner to check for a condition and signal the event.
  //
  if (!MockEvent->IsSignaled &&
      (MockEvent->Type & EVT_NOTIFY_WAIT) != 0 &&
      MockEvent->NotifyFunction != NULL)
  {
    MockEvent->NotifyFunction (Event, MockEvent->NotifyContext);
  }

  if (MockEvent->IsSignaled) {
    //
    // §7.1.6: Clear signaled state and return SUCCESS
    //
    MockEvent->IsSignaled = FALSE;
    return EFI_SUCCESS;
  }

  return EFI_NOT_READY;
}
