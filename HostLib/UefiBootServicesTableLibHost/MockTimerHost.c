/** @file MockTimerHost.c
    Host-based timer simulation layer.

    This file provides the host-specific timer API that sits on top of the
    real DXE Core timer logic (TimerDxeCore.c).  It replaces the old
    EventHost.c timer simulation with a hardware-accurate interrupt-pending
    model:

    - MockTimerAdvance100ns() advances simulated time.  If TPL is at
      TPL_HIGH_LEVEL, the duration is accumulated in gPendingTimerDuration
      (interrupt pending).  If TPL is below HIGH, CoreTimerTick() is called
      directly to process the time immediately.
    - TplDxeCore.c's CoreRestoreTpl calls MockTimerHostConsumePending()
      when dropping below HIGH to process any accumulated pending time.
    - MockTimerInit() registers the advance function with the pump.
    - MockEventResetState() resets all event/timer state per iteration.

    This design matches real hardware semantics:
      - Timer interrupts are masked at TPL_HIGH_LEVEL
      - Pending interrupts are processed when TPL drops below HIGH
      - CoreTimerTick() is the ISR entry point (from TimerDxeCore.c)

    Close-Event Listener Infrastructure:
    - Provides register/unregister/notify/reset for close-event callbacks.
    - Used by mock protocols to clear references when events are closed.

    Copyright (c) 2025, HBFAplus Contributors. All rights reserved.
    SPDX-License-Identifier: BSD-2-Clause-Patent
**/

#include "DxeMain.h"
#include "EventDxeCore.h"
#include "MockEventHost.h"
#include <Library/FuzzContextLib.h>

//
// ============================================================================
// Forward declarations from other DXE Core files
// ============================================================================
//

/**
  CoreTimerTick - ISR entry point from TimerDxeCore.c.
  Defined in TimerDxeCore.c.
**/
VOID
EFIAPI
CoreTimerTick (
  IN UINT64  Duration
  );

/**
  CoreInitializeEventServices - from EventDxeCore.c.
**/
EFI_STATUS
CoreInitializeEventServices (
  VOID
  );

/**
  HostShimInitRuntime - from HostShim.c.
**/
VOID
EFIAPI
HostShimInitRuntime (
  VOID
  );

//
// ============================================================================
// Extern declarations for DXE Core state we need to reset
// ============================================================================
//

///
/// From EventDxeCore.c — event queues and signal queue.
///
extern LIST_ENTRY  gEventQueue[];
extern LIST_ENTRY  gEventSignalQueue;
extern EFI_LOCK    gEventQueueLock;
extern EFI_EVENT   gIdleLoopEvent;

///
/// From TimerDxeCore.c — timer list and system time.
///
extern LIST_ENTRY  mEfiTimerList;
extern EFI_LOCK    mEfiTimerLock;
extern EFI_EVENT   mEfiCheckTimerEvent;
extern EFI_LOCK    mEfiSystemTimeLock;
extern UINT64      mEfiSystemTime;

//
// ============================================================================
// Global State - Timer Interrupt Pending Model
// ============================================================================
//

/**
  Accumulated timer duration that was "masked" by TPL_HIGH_LEVEL.
  When MockTimerAdvance100ns is called while gEfiCurrentTpl >= TPL_HIGH_LEVEL,
  the duration is added here instead of being processed immediately.
  CoreRestoreTpl consumes this via MockTimerHostConsumePending().
**/
STATIC UINT64  gPendingTimerDuration = 0;

/**
  Flag indicating if the timer system has been initialized.
**/
STATIC BOOLEAN  gTimerHostInitialized = FALSE;

//
// ============================================================================
// Global State - Pump Context
// ============================================================================
//

/**
  Global advance context used by CoreRestoreTpl() auto-advance and
  by the harness.  Set via MockEventSetAdvanceContext().
**/
MOCK_FUZZ_CONTEXT  *gMockEventAdvanceContext = NULL;

//
// ============================================================================
// Pump Context API
// ============================================================================
//

/**
  Set the global fuzz advance context for auto-time-advance.

  @param[in]  Ctx  Fuzz context to use, or NULL to disable.
**/
VOID
EFIAPI
MockEventSetAdvanceContext (
  IN MOCK_FUZZ_CONTEXT  *Ctx
  )
{
  gMockEventAdvanceContext = Ctx;
}

/**
  Get the current advance context.

  @return  Current advance context, or NULL if not set.
**/
MOCK_FUZZ_CONTEXT *
EFIAPI
MockEventHostGetAdvanceContext (
  VOID
  )
{
  return gMockEventAdvanceContext;
}

//
// ============================================================================
// Timer Host API
// ============================================================================
//

/**
  Initialize the mock timer service (one-time setup).

  Initializes the DXE Core event subsystem (event queues, timer list,
  idle loop event, mEfiCheckTimerEvent) and registers the timer advance
  function with the pump.

  Idempotent — safe to call more than once.
**/
VOID
EFIAPI
MockTimerInit (
  VOID
  )
{
  MOCK_FUZZ_CONTEXT  *Pool;

  if (gTimerHostInitialized) {
    return;
  }

  //
  // Initialize the runtime template's EventHead list.
  //
  HostShimInitRuntime ();

  //
  // Initialize the real DXE Core event services.
  // This sets up gEventQueue[], gEventSignalQueue, timer list,
  // mEfiCheckTimerEvent, and gIdleLoopEvent.
  //
  CoreInitializeEventServices ();

  gTimerHostInitialized = TRUE;

  //
  // Register MockTimerAdvance as the pump timer callback.
  //
  Pool = MockFuzzContextGetPool ();
  Pool->TimerAdvanceFn = MockTimerAdvance;

  DEBUG ((DEBUG_INFO, "MockTimerInit: DXE Core event services initialized\n"));
}

/**
  Advance simulated time by the specified number of microseconds.

  @param[in]  Microseconds  Time to advance in microseconds.
**/
VOID
EFIAPI
MockTimerAdvance (
  IN UINT64  Microseconds
  )
{
  MockTimerAdvance100ns (Microseconds * 10);
}

/**
  Advance simulated time by the specified number of 100ns units.

  If TPL is at TPL_HIGH_LEVEL, the duration is accumulated as a pending
  timer interrupt.  Otherwise, CoreTimerTick is called directly.

  @param[in]  Time100ns  Time to advance in 100ns units.
**/
VOID
EFIAPI
MockTimerAdvance100ns (
  IN UINT64  Time100ns
  )
{
  if (!gTimerHostInitialized) {
    DEBUG ((DEBUG_WARN, "MockTimerAdvance100ns: Timer not initialized\n"));
    return;
  }

  if (Time100ns == 0) {
    return;
  }

  //
  // Interrupt-pending model: if at TPL_HIGH, accumulate.
  // CoreRestoreTpl will consume via MockTimerHostConsumePending().
  //
  if (gEfiCurrentTpl >= TPL_HIGH_LEVEL) {
    gPendingTimerDuration += Time100ns;
    return;
  }

  //
  // Below HIGH: process immediately via CoreTimerTick.
  // CoreTimerTick updates mEfiSystemTime and signals mEfiCheckTimerEvent
  // if any timers have expired.
  //
  CoreTimerTick (Time100ns);

  //
  // Force dispatch of queued event notifies.  CoreTimerTick signals the
  // check-timer event, but its notify function (CoreCheckTimers) only runs
  // when event notifies are dispatched.  In real firmware this happens when
  // the hardware timer ISR returns via RestoreTpl.  Simulate that here by
  // doing a RaiseTpl/RestoreTpl pair which triggers CoreDispatchEventNotifies
  // for all pending TPL levels.
  //
  if (gEventPending != 0) {
    EFI_TPL  SavedTpl;
    SavedTpl = CoreRaiseTpl (TPL_HIGH_LEVEL);
    CoreRestoreTpl (SavedTpl);
  }
}

/**
  Consume any pending timer interrupt duration.

  Called by CoreRestoreTpl when dropping below TPL_HIGH_LEVEL.

  @return  The accumulated pending duration in 100ns units, or 0 if none.
**/
UINT64
EFIAPI
MockTimerHostConsumePending (
  VOID
  )
{
  UINT64  Duration;

  Duration = gPendingTimerDuration;
  gPendingTimerDuration = 0;
  return Duration;
}

/**
  Get the current simulated system time.

  @return  Current simulated time in 100ns units.
**/
UINT64
EFIAPI
MockTimerGetSystemTime (
  VOID
  )
{
  return mEfiSystemTime;
}

//
// ============================================================================
// Per-Iteration Reset
// ============================================================================
//

/**
  Reset ALL event and timer state for a new fuzz iteration.

  This is the single per-iteration reset entry point.  It resets:
    1. Timer list (mEfiTimerList → empty)
    2. Event queues (gEventQueue[] → empty, gEventSignalQueue → empty)
    3. gEventPending → 0
    4. mEfiSystemTime → 0
    5. gPendingTimerDuration → 0
    6. gEfiCurrentTpl → TPL_APPLICATION
    7. Close-event listeners
    8. Pump context → NULL
    9. Re-initializes event services (queues, timer, idle loop event)

  Call at the top of each fuzz iteration.
**/
VOID
EFIAPI
MockEventResetState (
  VOID
  )
{
  UINTN  Index;

  //
  // 1. Clear event pending bitmask.
  //
  gEventPending = 0;

  //
  // 2. Reinitialize event queues.
  //
  for (Index = 0; Index <= TPL_HIGH_LEVEL; Index++) {
    InitializeListHead (&gEventQueue[Index]);
  }

  //
  // 3. Reinitialize signal queue.
  //
  InitializeListHead (&gEventSignalQueue);

  //
  // 4. Reinitialize timer list.
  //
  InitializeListHead (&mEfiTimerList);

  //
  // 5. Reset system time and pending duration.
  //
  mEfiSystemTime = 0;
  gPendingTimerDuration = 0;

  //
  // 6. Restore TPL.
  //
  gEfiCurrentTpl = TPL_APPLICATION;

  //
  // 7. Clear pump context.
  //
  gMockEventAdvanceContext = NULL;

  //
  // 8. Clear the idle loop event (will be recreated).
  //
  gIdleLoopEvent = NULL;

  //
  // 9. Clear the check timer event (will be recreated by CoreInitializeTimer).
  //
  mEfiCheckTimerEvent = NULL;

  //
  // 10. Re-initialize event services: creates mEfiCheckTimerEvent
  //     and gIdleLoopEvent fresh.
  //
  HostShimInitRuntime ();
  CoreInitializeEventServices ();

  //
  // 11. Re-register the timer advance callback.
  //
  {
    MOCK_FUZZ_CONTEXT  *Pool;
    Pool = MockFuzzContextGetPool ();
    Pool->TimerAdvanceFn = MockTimerAdvance;
  }

  DEBUG ((DEBUG_VERBOSE, "MockEventResetState: All event/timer state reset\n"));
}
