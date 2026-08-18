/** @file MockDeferredSignal.c
    Timer-deferred token signal utility — implementation.

    See MockDeferredSignal.h for architecture overview and API documentation.

    Copyright (c) 2025, HBFAplus Contributors. All rights reserved.
    SPDX-License-Identifier: BSD-2-Clause-Patent
**/

#include <Library/MockDeferredSignal.h>

#include <Uefi.h>
#include <Library/BaseLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/DebugLib.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Protocol/Dpc.h>

//
// Forward declarations of DXE Core services used directly.
// We call these rather than going through gBS to avoid any shim overhead
// and to ensure we always reach the real implementation.
//
extern EFI_STATUS EFIAPI CoreCreateEvent (
  IN  UINT32            Type,
  IN  EFI_TPL           NotifyTpl,
  IN  EFI_EVENT_NOTIFY  NotifyFunction  OPTIONAL,
  IN  VOID              *NotifyContext  OPTIONAL,
  OUT EFI_EVENT         *Event
  );

extern EFI_STATUS EFIAPI CoreSetTimer (
  IN EFI_EVENT        Event,
  IN EFI_TIMER_DELAY  Type,
  IN UINT64           TriggerTime
  );

extern EFI_STATUS EFIAPI CoreCloseEvent (
  IN EFI_EVENT  Event
  );

extern EFI_STATUS EFIAPI CoreSignalEvent (
  IN EFI_EVENT  Event
  );

//
// Global advance context — when non-NULL we are in fuzz/deferred mode
// and must defer signaling via one-shot timers to prevent infinite
// re-arm loops.  When NULL (unit-test default), we signal immediately.
// Defined in MockTimerHost.c.
//
typedef struct MOCK_FUZZ_CONTEXT MOCK_FUZZ_CONTEXT;
extern MOCK_FUZZ_CONTEXT  *gMockEventAdvanceContext;

//=============================================================================
// Internal — DispatchDpc helper
//=============================================================================

/**
  Locate the DPC protocol and call DispatchDpc to drain queued DPCs.

  This matches real edk2 driver behavior where protocol functions
  (Udp4Main.c, Ip4Impl.c, etc.) explicitly call DispatchDpc() after
  signaling completion events, ensuring DPC handlers run at controlled
  points.

  Safe no-op if the DPC protocol is not installed.
**/
STATIC
VOID
DrainDpcQueue (
  VOID
  )
{
  EFI_DPC_PROTOCOL  *DpcProtocol;
  EFI_STATUS        Status;

  Status = gBS->LocateProtocol (&gEfiDpcProtocolGuid, NULL, (VOID **)&DpcProtocol);
  if (!EFI_ERROR (Status)) {
    DpcProtocol->DispatchDpc (DpcProtocol);
  }
}

//=============================================================================
// Internal — Timer delivery callback
//=============================================================================

/**
  One-shot timer callback.  Fires during the next CoreTimerTick after scheduling.

  1. Signals the original token event (e.g., MNP receive completion).
  2. Dispatches any DPCs queued as a result of the signal.
  3. Removes this entry from the pending list and frees it.
  4. Closes the delivery timer event.

  @param[in]  Event    The delivery timer event (self).
  @param[in]  Context  Pointer to the MOCK_DEFERRED_ENTRY.
**/
STATIC
VOID
EFIAPI
DeliverCallback (
  IN EFI_EVENT  Event,
  IN VOID       *Context
  )
{
  MOCK_DEFERRED_ENTRY  *Entry;

  Entry = (MOCK_DEFERRED_ENTRY *)Context;
  if (Entry == NULL) {
    return;
  }

  DEBUG ((DEBUG_VERBOSE, "MockDeferred: DeliverCallback TokenEvent=%p Timer=%p\n",
          Entry->TokenEvent, Entry->DeliveryTimer));

  //
  // Step 1: Signal the original completion-token event.
  // This fires the EVT_NOTIFY_SIGNAL callback registered by the driver
  // (e.g., Ip4OnFrameReceived, UdpIoOnDgramRcvd), which typically calls
  // QueueDpc() to schedule actual packet processing.
  //
  if (Entry->TokenEvent != NULL) {
    CoreSignalEvent (Entry->TokenEvent);
  }

  //
  // Step 2: Dispatch DPCs queued by the signal.
  // Real edk2 drivers call DispatchDpc() at specific points after
  // signaling events.  We do it here in the delivery callback to
  // match that behavior — the DPC handler processes the packet data
  // that was filled by the mock Receive() function.
  //
  DrainDpcQueue ();

  //
  // Step 3: Remove from pending list and free.
  // The entry is unlinked AFTER dispatch so that CancelAll during a
  // DPC handler can still find and cancel other pending entries.
  //
  RemoveEntryList (&Entry->Link);
  FreePool (Entry);

  //
  // Step 4: Close the delivery timer event (self).
  // Must happen AFTER we're done using Entry, since CloseEvent may
  // trigger re-entrant notifications.
  //
  CoreCloseEvent (Event);
}

//=============================================================================
// Public API implementation
//=============================================================================

VOID
EFIAPI
MockDeferredInit (
  IN OUT MOCK_DEFERRED_STATE  *State
  )
{
  if (State == NULL) {
    return;
  }

  if (!State->Initialized) {
    InitializeListHead (&State->PendingList);
    State->Initialized = TRUE;
  }
}

EFI_STATUS
EFIAPI
MockDeferredSchedule (
  IN OUT MOCK_DEFERRED_STATE  *State,
  IN     EFI_EVENT             TokenEvent
  )
{
  EFI_STATUS            Status;
  MOCK_DEFERRED_ENTRY  *Entry;

  if ((State == NULL) || (TokenEvent == NULL)) {
    return EFI_INVALID_PARAMETER;
  }

  MockDeferredInit (State);

  //
  // Fast path: when no advance context is set (unit-test mode), signal
  // immediately instead of arming a timer.  The deferred timer approach
  // exists to prevent infinite re-arm loops during fuzzing; in unit tests
  // there is no fuzz pump loop so immediate signaling is safe and keeps
  // tests simple.
  //
  if (gMockEventAdvanceContext == NULL) {
    CoreSignalEvent (TokenEvent);
    DrainDpcQueue ();
    return EFI_SUCCESS;
  }

  //
  // Allocate a new entry.
  //
  Entry = AllocateZeroPool (sizeof (MOCK_DEFERRED_ENTRY));
  if (Entry == NULL) {
    DEBUG ((DEBUG_ERROR, "MockDeferred: Schedule OOM\n"));
    return EFI_OUT_OF_RESOURCES;
  }

  Entry->TokenEvent = TokenEvent;
  InitializeListHead (&Entry->Link);

  //
  // Create a one-shot timer event with notification callback.
  // EVT_TIMER enables SetTimer; EVT_NOTIFY_SIGNAL fires DeliverCallback
  // when the timer expires.
  //
  Status = CoreCreateEvent (
             EVT_TIMER | EVT_NOTIFY_SIGNAL,
             TPL_CALLBACK,
             DeliverCallback,
             Entry,
             &Entry->DeliveryTimer
             );
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, "MockDeferred: CreateEvent failed: %r\n", Status));
    FreePool (Entry);
    return Status;
  }

  //
  // Arm as TimerRelative with TriggerTime=1 (100ns).
  // CoreSetTimer sets absolute TriggerTime = SystemTime + 1.
  // CoreCheckTimers (called by CoreTimerTick in the next AdvanceTime)
  // compares TriggerTime <= SystemTime.  Since TriggerTime > current
  // SystemTime, it won't fire in the same tick — only on the NEXT tick.
  //
  Status = CoreSetTimer (Entry->DeliveryTimer, TimerRelative, 1);
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, "MockDeferred: SetTimer failed: %r\n", Status));
    CoreCloseEvent (Entry->DeliveryTimer);
    FreePool (Entry);
    return Status;
  }

  //
  // Add to the pending list.
  //
  InsertTailList (&State->PendingList, &Entry->Link);

  DEBUG ((DEBUG_VERBOSE, "MockDeferred: Scheduled TokenEvent=%p Timer=%p\n",
          TokenEvent, Entry->DeliveryTimer));

  return EFI_SUCCESS;
}

EFI_STATUS
EFIAPI
MockDeferredCancel (
  IN OUT MOCK_DEFERRED_STATE  *State,
  IN     EFI_EVENT             TokenEvent
  )
{
  LIST_ENTRY           *Link;
  MOCK_DEFERRED_ENTRY  *Entry;

  if ((State == NULL) || (TokenEvent == NULL)) {
    return EFI_NOT_FOUND;
  }

  if (!State->Initialized || IsListEmpty (&State->PendingList)) {
    return EFI_NOT_FOUND;
  }

  for (Link = GetFirstNode (&State->PendingList);
       !IsNull (&State->PendingList, Link);
       Link = GetNextNode (&State->PendingList, Link))
  {
    Entry = BASE_CR (Link, MOCK_DEFERRED_ENTRY, Link);
    if (Entry->TokenEvent == TokenEvent) {
      //
      // Cancel the timer, close it, unlink and free.
      //
      CoreSetTimer (Entry->DeliveryTimer, TimerCancel, 0);
      CoreCloseEvent (Entry->DeliveryTimer);
      RemoveEntryList (&Entry->Link);
      FreePool (Entry);

      DEBUG ((DEBUG_VERBOSE, "MockDeferred: Cancelled TokenEvent=%p\n", TokenEvent));
      return EFI_SUCCESS;
    }
  }

  return EFI_NOT_FOUND;
}

VOID
EFIAPI
MockDeferredCancelAll (
  IN OUT MOCK_DEFERRED_STATE  *State
  )
{
  LIST_ENTRY           *Link;
  LIST_ENTRY           *Next;
  MOCK_DEFERRED_ENTRY  *Entry;

  if ((State == NULL) || !State->Initialized) {
    return;
  }

  for (Link = GetFirstNode (&State->PendingList);
       !IsNull (&State->PendingList, Link);
       Link = Next)
  {
    Next  = GetNextNode (&State->PendingList, Link);
    Entry = BASE_CR (Link, MOCK_DEFERRED_ENTRY, Link);

    CoreSetTimer (Entry->DeliveryTimer, TimerCancel, 0);
    CoreCloseEvent (Entry->DeliveryTimer);
    RemoveEntryList (&Entry->Link);
    FreePool (Entry);
  }

  DEBUG ((DEBUG_VERBOSE, "MockDeferred: CancelAll complete\n"));
}

VOID
EFIAPI
MockDeferredReset (
  IN OUT MOCK_DEFERRED_STATE  *State
  )
{
  if (State == NULL) {
    return;
  }

  if (State->Initialized) {
    MockDeferredCancelAll (State);
  }

  //
  // Re-initialize to clean state.
  //
  InitializeListHead (&State->PendingList);
  State->Initialized = TRUE;
}


