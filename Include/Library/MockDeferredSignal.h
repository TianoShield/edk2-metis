/** @file MockDeferredSignal.h
    Timer-deferred token signal utility for mock protocols.

    Provides a shared mechanism for mock protocol Receive() functions to
    defer the signaling of completion-token events to the next AdvanceTime
    boundary.  This prevents the fuzz-data-eating loop that occurs when
    SignalEvent() fires synchronously inside a DPC dispatch chain:

      DPC handler -> Receive() -> SignalEvent -> callback -> QueueDpc -> loop

    With deferred signaling, Receive() only arms a one-shot timer instead:

      Receive() -> fill data -> MockDeferredSchedule() -> return
        ... next AdvanceTime tick ...
      timer fires -> DeliverCallback -> SignalEvent(token) -> DispatchDpc()

    Each mock protocol that uses async completion tokens (Receive, Transmit,
    Request) should embed a MOCK_DEFERRED_STATE and call these functions
    instead of gBS->SignalEvent(Token->Event) directly.

    Architecture Notes:
      - Uses CoreCreateEvent(EVT_TIMER | EVT_NOTIFY_SIGNAL) + CoreSetTimer(
        TimerRelative, 1) to create a one-shot timer that fires on the NEXT
        CoreTimerTick — verified: CoreSetTimer sets TriggerTime = SystemTime+1,
        and CoreCheckTimers skips timers where TriggerTime > SystemTime in
        the same tick.
      - The delivery callback signals the original token event AND calls
        DispatchDpc() to match real edk2 driver behavior where protocol
        functions explicitly dispatch queued DPCs.
      - Dynamic linked-list tracking (no fixed slot limit) — each pending
        delivery is a heap-allocated MOCK_DEFERRED_ENTRY removed on delivery
        or cancellation.
      - Cancel/CancelAll walk the list, cancel timers, close events, and
        free entries.  Used by protocol Cancel() and Configure(NULL).
      - Reset is called per fuzz iteration by MockEventResetState.

    Copyright (c) 2025, HBFAplus Contributors. All rights reserved.
    SPDX-License-Identifier: BSD-2-Clause-Patent
**/

#ifndef MOCK_DEFERRED_SIGNAL_H_
#define MOCK_DEFERRED_SIGNAL_H_

#include <Uefi.h>
#include <Library/BaseLib.h>

//
// ============================================================================
// Data Structures
// ============================================================================
//

///
/// A single pending deferred delivery.
/// Heap-allocated by MockDeferredSchedule, freed on delivery or cancellation.
///
typedef struct {
  LIST_ENTRY  Link;           ///< Linked into MOCK_DEFERRED_STATE.PendingList
  EFI_EVENT   TokenEvent;     ///< The original completion-token event to signal
  EFI_EVENT   DeliveryTimer;  ///< One-shot timer that fires the delivery callback
} MOCK_DEFERRED_ENTRY;

///
/// Per-protocol deferred signal state.
/// Each mock protocol embeds one of these as a STATIC module variable.
///
typedef struct {
  LIST_ENTRY  PendingList;    ///< List of MOCK_DEFERRED_ENTRY
  BOOLEAN     Initialized;    ///< TRUE after MockDeferredInit()
} MOCK_DEFERRED_STATE;

//
// ============================================================================
// Public API
// ============================================================================
//

/**
  Initialize deferred signal state.  Idempotent — safe to call more than once.

  @param[in,out]  State  Per-protocol deferred state to initialize.
**/
VOID
EFIAPI
MockDeferredInit (
  IN OUT MOCK_DEFERRED_STATE  *State
  );

/**
  Schedule a deferred delivery of a token event.

  Creates a one-shot timer (EVT_TIMER | EVT_NOTIFY_SIGNAL) with
  TriggerTime = 1 (100ns units).  When the timer fires during the next
  AdvanceTime tick, the delivery callback:
    1. Signals TokenEvent via gBS->SignalEvent()
    2. Calls DispatchDpc() to drain any DPCs queued by the signal
    3. Removes and frees the MOCK_DEFERRED_ENTRY

  @param[in,out]  State       Per-protocol deferred state.
  @param[in]      TokenEvent  The completion token's EFI_EVENT to signal.
                              Must not be NULL.

  @retval  EFI_SUCCESS            Timer armed successfully.
  @retval  EFI_INVALID_PARAMETER  State or TokenEvent is NULL.
  @retval  EFI_OUT_OF_RESOURCES   Memory allocation failed.
  @retval  other                  CreateEvent or SetTimer failure.
**/
EFI_STATUS
EFIAPI
MockDeferredSchedule (
  IN OUT MOCK_DEFERRED_STATE  *State,
  IN     EFI_EVENT             TokenEvent
  );

/**
  Cancel a specific pending deferred delivery.

  Walks the pending list, cancels the timer, closes the timer event,
  removes the entry, and frees memory.  Does NOT signal the token event.

  @param[in,out]  State       Per-protocol deferred state.
  @param[in]      TokenEvent  The token event to cancel.

  @retval  EFI_SUCCESS    Entry found and cancelled.
  @retval  EFI_NOT_FOUND  No pending entry with this TokenEvent.
**/
EFI_STATUS
EFIAPI
MockDeferredCancel (
  IN OUT MOCK_DEFERRED_STATE  *State,
  IN     EFI_EVENT             TokenEvent
  );

/**
  Cancel ALL pending deferred deliveries for this protocol.

  Used by Configure(NULL) and iteration-boundary reset.
  Does NOT signal any token events.

  @param[in,out]  State  Per-protocol deferred state.
**/
VOID
EFIAPI
MockDeferredCancelAll (
  IN OUT MOCK_DEFERRED_STATE  *State
  );

/**
  Reset deferred state for a new fuzz iteration.

  Cancels all pending entries and re-initializes the list.
  Called by each mock's ResetState, which is invoked by MockEventResetState
  via MockProtocolRegisterReset.

  @param[in,out]  State  Per-protocol deferred state.
**/
VOID
EFIAPI
MockDeferredReset (
  IN OUT MOCK_DEFERRED_STATE  *State
  );

#endif // MOCK_DEFERRED_SIGNAL_H_
