/** @file MockEventHost.h
    Public API for the host-based event/timer system.

    This header is the single public interface for harnesses, tests, and mock
    protocols to interact with the host event/timer subsystem.  It replaces
    the old Event.h which exposed MOCK_EVENT internals.

    The internal event structure (IEVENT) is now the real DXE Core structure
    from EventDxeCore.h.  This header does NOT expose IEVENT — consumers
    interact only through EFI_EVENT handles and the mock API functions below.

    Architecture:
      EventDxeCore.c  — Real DXE Core event logic (CoreCreate/Signal/Close/Check)
      TimerDxeCore.c  — Real DXE Core timer logic (CoreSetTimer/CoreTimerTick)
      TplDxeCore.c    — Real DXE Core TPL logic (CoreRaiseTpl/CoreRestoreTpl)
      HostShim.c      — Hardware stubs (gCpu=NULL, gRuntime, etc.)
      MockTimerHost.c — Host timer simulation (MockTimerAdvance, reset, listeners)

    Copyright (c) 2025, HBFAplus Contributors. All rights reserved.
    SPDX-License-Identifier: BSD-2-Clause-Patent
**/

#ifndef __MOCK_EVENT_HOST_H__
#define __MOCK_EVENT_HOST_H__

#include <Uefi.h>
#include <Library/FuzzContextLib.h>

//
// ============================================================================
// Pump Context API
// ============================================================================
//

/**
  Set the global fuzz advance context for auto-time-advance.

  When set, CoreRestoreTpl() auto-advance uses this context to drive
  timer events via MockFuzzContextAdvanceTime().

  @param[in]  Ctx  Fuzz context to use, or NULL to disable.
**/
VOID
EFIAPI
MockEventSetAdvanceContext (
  IN MOCK_FUZZ_CONTEXT  *Ctx
  );

/**
  Get the current advance context.

  @return  Current advance context, or NULL if not set.
**/
MOCK_FUZZ_CONTEXT *
EFIAPI
MockEventHostGetAdvanceContext (
  VOID
  );

//
// ============================================================================
// Timer Host API
// ============================================================================
//

/**
  Initialize the mock timer service (one-time setup).

  Initializes the DXE Core event subsystem and registers the timer
  advance function with the pump.  Idempotent.
**/
VOID
EFIAPI
MockTimerInit (
  VOID
  );

/**
  Advance simulated time by the specified number of microseconds.

  @param[in]  Microseconds  Time to advance in microseconds.
**/
VOID
EFIAPI
MockTimerAdvance (
  IN UINT64  Microseconds
  );

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
  );

/**
  Consume any pending timer interrupt duration.

  Called by CoreRestoreTpl when dropping below TPL_HIGH_LEVEL.

  @return  Accumulated pending duration in 100ns units, or 0 if none.
**/
UINT64
EFIAPI
MockTimerHostConsumePending (
  VOID
  );

/**
  Get the current simulated system time.

  @return  Current simulated time in 100ns units.
**/
UINT64
EFIAPI
MockTimerGetSystemTime (
  VOID
  );

//
// ============================================================================
// Per-Iteration Reset
// ============================================================================
//

/**
  Reset ALL event and timer state for a new fuzz iteration.

  Resets event queues, timer list, system time, TPL, close listeners,
  and re-initializes the DXE Core event services.

  Call at the top of each fuzz iteration.
**/
VOID
EFIAPI
MockEventResetState (
  VOID
  );

//
// ============================================================================
// Boot Services Event Function Prototypes
// ============================================================================
//

EFI_STATUS
EFIAPI
CoreCreateEvent (
  IN  UINT32            Type,
  IN  EFI_TPL           NotifyTpl,
  IN  EFI_EVENT_NOTIFY  NotifyFunction  OPTIONAL,
  IN  VOID              *NotifyContext  OPTIONAL,
  OUT EFI_EVENT         *Event
  );

EFI_STATUS
EFIAPI
CoreCreateEventEx (
  IN       UINT32            Type,
  IN       EFI_TPL           NotifyTpl,
  IN       EFI_EVENT_NOTIFY  NotifyFunction  OPTIONAL,
  IN CONST VOID              *NotifyContext  OPTIONAL,
  IN CONST EFI_GUID          *EventGroup     OPTIONAL,
  OUT      EFI_EVENT         *Event
  );

EFI_STATUS
EFIAPI
CoreSetTimer (
  IN EFI_EVENT        Event,
  IN EFI_TIMER_DELAY  Type,
  IN UINT64           TriggerTime
  );

EFI_STATUS
EFIAPI
CoreWaitForEvent (
  IN  UINTN      NumberOfEvents,
  IN  EFI_EVENT  *Event,
  OUT UINTN      *Index
  );

EFI_STATUS
EFIAPI
CoreSignalEvent (
  IN EFI_EVENT  Event
  );

EFI_STATUS
EFIAPI
CoreCloseEvent (
  IN EFI_EVENT  Event
  );

EFI_STATUS
EFIAPI
CoreCheckEvent (
  IN EFI_EVENT  Event
  );

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
// ============================================================================
// Removed APIs (backward compatibility stubs / notes)
// ============================================================================
//
// The following APIs from the old Event.h are REMOVED:
//
//   gMockTimerFireOnSetTimer    — Fire-on-SetTimer removed entirely.
//   gMockAutoAdvanceOnRestoreTpl  — Auto-pump on RestoreTpl removed entirely.
//   MockEventSetAutoAdvanceOnRestoreTpl() — Removed.
//   MockTplResetAutoAdvanceState()        — Removed.
//   MockDispatchEventNotifies()        — Replaced by real CoreDispatchEventNotifies.
//   MockEventSignal()                  — Replaced by real CoreSignalEvent.
//   MOCK_EVENT / gMockEvents[]         — Replaced by real IEVENT (heap-allocated).
//   IsValidMockEvent()                 — Replaced by Signature check in DXE Core.
//
// Harnesses that previously used these should:
//   - Use MockTimerAdvance100ns() to drive timer events
//   - Use MockFuzzContextAdvanceTime() for explicit event pumping
//   - Use CoreSignalEvent() directly to signal events
//

#endif // __MOCK_EVENT_HOST_H__
