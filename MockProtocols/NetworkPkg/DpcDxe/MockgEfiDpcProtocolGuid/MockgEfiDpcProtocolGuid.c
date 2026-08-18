/** @file MockgEfiDpcProtocolGuid.c
    Mock implementation of EFI_DPC_PROTOCOL (gEfiDpcProtocolGuid).

    The Deferred Procedure Call (DPC) protocol is used by DxeDpcLib (which is
    in turn consumed by DxeUdpIoLib, DxeIpIoLib, and many other NetworkPkg
    libraries) to queue and dispatch callback procedures.

    This mock now matches real edk2 DpcDxe semantics:
    - QueueDpc: RaiseTpl(HIGH) → add to queue → RestoreTpl(Original).
      NO auto-drain.  DPCs are dispatched only when DispatchDpc() is
      called explicitly by driver code (e.g., Ip4Dxe calls DispatchDpc()
      after Transmit, Receive, Routes, etc.).
    - DispatchDpc: Drains the queue, invoking each DPC procedure.

    This prevents the unbounded stack growth that occurs with inline
    invoke models (QueueDpc → handler → QueueDpc → handler → …) and
    ensures DPCs run at controlled points where driver state is consistent.

    Deviation from real edk2 implementation:
    - This mock does NOT enforce TPL-based priority ordering — all DPCs are
      dispatched FIFO.  Real edk2 DpcDxe maintains per-TPL queues and
      dispatches from highest to lowest.  This is acceptable because the
      host fuzzing environment has simplified TPL management.
    - QueueDpc deduplicates entries: if an identical (Procedure, Context)
      pair is already pending, the new entry is silently dropped.  Real edk2
      does not deduplicate because one-shot MNP hardware events prevent
      duplicate queueing in practice.  The mock advance mechanism can re-signal
      the same event across multiple AdvanceTime calls, creating duplicates
      that would cause use-after-free on dispatch (see CRASH-FIX comment
      in MockDpcQueueDpc).

    Installation:
    - The constructor locates gFuzzHandle (shared mock handle) and installs
      gEfiDpcProtocolGuid so that DpcLibConstructor's LocateProtocol succeeds.

    Reusability:
    - This mock is independent of any specific driver — it can be consumed by
      any harness that links DxeDpcLib or any library depending on DPC.

    Copyright (c) 2025, HBFAplus Contributors. All rights reserved.
    SPDX-License-Identifier: BSD-2-Clause-Patent
**/

//=============================================================================
// UEFI Spec Audit — EFI_DPC_PROTOCOL (Deferred Procedure Call)
//
// Real UEFI: DPC provides a priority-based deferred callback mechanism.
//   QueueDpc adds a procedure to a per-TPL queue.
//   DispatchDpc executes all queued procedures at or above the current TPL.
//   Dispatch occurs only when explicitly called (no auto-drain).
//   Real edk2 DpcQueueDpc does: RaiseTpl(HIGH) → add to queue →
//   RestoreTpl(Original).  Real edk2 DpcDispatchDpc does:
//   RaiseTpl(HIGH) → loop from HIGH down to OriginalTpl → drain each
//   level's queue → RestoreTpl(Original).
// Our mock:  Matches real edk2 queue semantics. QueueDpc adds to a FIFO
//   ring buffer with RaiseTpl/RestoreTpl.  DispatchDpc drains the queue
//   explicitly when called by driver code.  No auto-drain in QueueDpc.
// Deviations:
//   1. No TPL-based priority ordering — all DPCs are dispatched FIFO.
//      DpcTpl values are validated but not used for ordering.
//   2. DispatchDpc runs procedures at the caller's TPL, not per-DPC TPL.
//   3. QueueDpc deduplicates: silently drops entries when the same
//      (Procedure, Context) pair is already pending.  Prevents mock-advance
//      re-signaling artifacts from generating duplicate DPC entries that
//      would cause use-after-free on dispatch.
// Corner cases:
//   - Re-entrant QueueDpc (handler queues another DPC) is safe — the
//     entry is appended to the queue for the caller's dispatch loop.
//   - Ring buffer overflow (>32 pending DPCs) returns EFI_OUT_OF_RESOURCES.
//=============================================================================

#include <Uefi.h>
#include <Library/DebugLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Library/FuzzContextLib.h>
#include <Protocol/Dpc.h>

//=============================================================================
// External — shared mock handle
//=============================================================================

extern EFI_HANDLE  gFuzzHandle;

//=============================================================================
// DPC Queue — breadth-first dispatch
//=============================================================================

///
/// Maximum number of DPC entries that can be queued simultaneously.
/// 32 is generous; in practice the depth rarely exceeds 3-4.
/// If exceeded, QueueDpc returns EFI_OUT_OF_RESOURCES and the DPC is dropped.
///
#define MOCK_DPC_MAX_QUEUE  32

typedef struct {
  EFI_DPC_PROCEDURE  Procedure;
  VOID               *Context;
} MOCK_DPC_ENTRY;

STATIC MOCK_DPC_ENTRY  mDpcQueue[MOCK_DPC_MAX_QUEUE];
STATIC UINT32          mDpcHead          = 0;   ///< Ring index: next entry to dispatch
STATIC UINT32          mDpcTail          = 0;   ///< Ring index: next free slot
STATIC UINT32          mDpcCount         = 0;   ///< Current number of entries in ring
STATIC BOOLEAN         mInsideDispatch   = FALSE;

//=============================================================================
// Counters
//=============================================================================

STATIC UINT32  mMockDpcQueueCount    = 0;   ///< Total DPCs queued (lifetime)
STATIC UINT32  mMockDpcDispatchCount = 0;   ///< Total DPCs dispatched (lifetime)

//=============================================================================
// Internal — drain the queue
//=============================================================================

/**
  Drain all pending DPC entries from the queue.

  While draining, handlers may call QueueDpc again (re-entrant path).
  Those new entries are appended to the tail and processed by this same
  loop iteration — breadth-first, constant stack depth.

  @return Number of DPCs dispatched in this drain pass.
**/
STATIC
UINT32
MockDpcDrainQueue (
  VOID
  )
{
  UINT32             Dispatched;
  EFI_DPC_PROCEDURE  Proc;
  VOID               *Ctx;

  if (mInsideDispatch) {
    //
    // Already draining — the caller is a DPC handler that re-entered
    // QueueDpc.  The outer loop will pick up the new entry.
    //
    return 0;
  }

  mInsideDispatch = TRUE;
  Dispatched      = 0;

  while (mDpcCount > 0) {
    Proc = mDpcQueue[mDpcHead].Procedure;
    Ctx  = mDpcQueue[mDpcHead].Context;
    mDpcHead = (mDpcHead + 1) % MOCK_DPC_MAX_QUEUE;
    mDpcCount--;

    DEBUG ((DEBUG_VERBOSE, "MockDpc: Dispatch[%u] proc=%p ctx=%p\n",
            Dispatched, Proc, Ctx));

    Proc (Ctx);
    Dispatched++;
    mMockDpcDispatchCount++;
  }

  mInsideDispatch = FALSE;
  return Dispatched;
}

//=============================================================================
// Protocol function implementations
//=============================================================================

/**
  Queue a DPC for later dispatch.

  Matches real edk2 DpcQueueDpc (NetworkPkg/DpcDxe/Dpc.c):
    RaiseTpl(HIGH) → add to queue → RestoreTpl(Original).
  NO auto-drain.  DPCs are dispatched only when DispatchDpc() is
  called explicitly by driver code.

  The RestoreTpl may dispatch pending event notifications (via
  CoreRestoreTpl's dispatch loop), but it does NOT drain the DPC
  queue — that only happens via DispatchDpc().
**/
STATIC
EFI_STATUS
EFIAPI
MockDpcQueueDpc (
  IN EFI_DPC_PROTOCOL   *This,
  IN EFI_TPL            DpcTpl,
  IN EFI_DPC_PROCEDURE  DpcProcedure,
  IN VOID               *DpcContext    OPTIONAL
  )
{
  EFI_TPL  OriginalTpl;

  if (DpcProcedure == NULL) {
    return EFI_INVALID_PARAMETER;
  }

  //
  // Validate DpcTpl range per protocol spec.
  // Real edk2 DpcDxe (Dpc.c) rejects TPLs outside [TPL_APPLICATION, TPL_HIGH_LEVEL].
  //
  if ((DpcTpl < TPL_APPLICATION) || (DpcTpl > TPL_HIGH_LEVEL)) {
    return EFI_INVALID_PARAMETER;
  }

  //
  // Match real edk2: RaiseTpl(HIGH) for queue manipulation, then
  // RestoreTpl(Original) — which may dispatch pending events but
  // does NOT auto-drain the DPC queue.
  //
  OriginalTpl = gBS->RaiseTPL (TPL_HIGH_LEVEL);

  if (mDpcCount >= MOCK_DPC_MAX_QUEUE) {
    DEBUG ((DEBUG_ERROR, "MockDpc: Queue full (%u entries) — dropping DPC proc=%p\n",
            MOCK_DPC_MAX_QUEUE, DpcProcedure));
    gBS->RestoreTPL (OriginalTpl);
    return EFI_OUT_OF_RESOURCES;
  }

  //
  // CRASH-FIX: Deduplicate — reject if (Procedure, Context) already queued.
  //
  // Root cause: The mock advance mechanism (MockFuzzContextAdvanceTime) re-signals
  // ALL registered advance events every time it fires.  During InitializeHarness,
  // multiple CoreRestoreTpl(APPLICATION) calls each trigger auto-advance, and each
  // advance re-signals the MNP completion token's event.  Each signal fires
  // Ip4OnFrameReceived → QueueDpc(Ip4OnFrameReceivedDpc, same_Token).  Without
  // dedup, the same DPC accumulates N times.  When DispatchDpc runs, the first
  // dispatch frees the Token and the second dispatch hits use-after-free
  // (ASSERT at Ip4If.c:1224 NET_CHECK_SIGNATURE).
  //
  // In real edk2, this scenario doesn't occur because MNP completion events are
  // one-shot: the NIC signals the event once per Receive() call, and a new
  // Receive() must be posted to get another signal.  The mock's advance-all-events
  // pattern is an artifact that doesn't match real hardware behavior.
  //
  // Deduplication is safe because a DPC with the same function and context
  // already pending in the queue means the work will be done — enqueueing it
  // again would only cause double-processing of the same data.
  //
  {
    UINT32  Idx;
    UINT32  Pos;

    Pos = mDpcHead;
    for (Idx = 0; Idx < mDpcCount; Idx++) {
      if (mDpcQueue[Pos].Procedure == DpcProcedure &&
          mDpcQueue[Pos].Context   == DpcContext)
      {
        DEBUG ((DEBUG_VERBOSE, "MockDpc: QueueDpc DEDUP — (proc=%p ctx=%p) already queued, skipping\n",
                DpcProcedure, DpcContext));
        gBS->RestoreTPL (OriginalTpl);
        return EFI_SUCCESS;
      }
      Pos = (Pos + 1) % MOCK_DPC_MAX_QUEUE;
    }
  }

  mDpcQueue[mDpcTail].Procedure = DpcProcedure;
  mDpcQueue[mDpcTail].Context   = DpcContext;
  mDpcTail = (mDpcTail + 1) % MOCK_DPC_MAX_QUEUE;
  mDpcCount++;
  mMockDpcQueueCount++;

  DEBUG ((DEBUG_VERBOSE, "MockDpc: QueueDpc (proc=%p ctx=%p) count=%u\n",
          DpcProcedure, DpcContext, mDpcCount));

  //
  // Match real edk2: RestoreTpl(Original).  Any pending event
  // notifications are dispatched by CoreRestoreTpl's dispatch loop.
  // DPC queue is NOT drained here — that's DispatchDpc's job.
  //
  gBS->RestoreTPL (OriginalTpl);

  return EFI_SUCCESS;
}

/**
  Dispatch any pending DPCs.

  Unlike the auto-drain in QueueDpc, DispatchDpc is an *explicit* drain
  request.  Real edk2 DpcDxe (Dpc.c) dispatches re-entrantly — it uses
  TPL_HIGH_LEVEL to serialize, but it does NOT skip dispatch when called
  from inside a DPC handler.  We match that: save/restore mInsideDispatch
  so the drain proceeds even if we are already inside a dispatch loop.
  This is critical because callers like UdpIo Cancel+FreeIo rely on
  DispatchDpc to synchronously flush deferred DPCs before freeing memory.
**/
STATIC
EFI_STATUS
EFIAPI
MockDpcDispatchDpc (
  IN EFI_DPC_PROTOCOL  *This
  )
{
  UINT32             Dispatched;
  EFI_DPC_PROCEDURE  Proc;
  VOID               *Ctx;
  BOOLEAN            SavedInsideDispatch;

  //
  // Save and override the re-entrancy flag so we drain unconditionally.
  //
  SavedInsideDispatch = mInsideDispatch;
  mInsideDispatch     = TRUE;
  Dispatched          = 0;

  while (mDpcCount > 0) {
    Proc = mDpcQueue[mDpcHead].Procedure;
    Ctx  = mDpcQueue[mDpcHead].Context;
    mDpcHead = (mDpcHead + 1) % MOCK_DPC_MAX_QUEUE;
    mDpcCount--;

    DEBUG ((DEBUG_VERBOSE, "MockDpc: DispatchDpc[%u] proc=%p ctx=%p\n",
            Dispatched, Proc, Ctx));

    Proc (Ctx);
    Dispatched++;
    mMockDpcDispatchCount++;
  }

  mInsideDispatch = SavedInsideDispatch;

  if (Dispatched == 0) {
    return EFI_NOT_FOUND;
  }

  DEBUG ((DEBUG_INFO, "MockDpc: DispatchDpc drained %u entries\n", Dispatched));
  return EFI_SUCCESS;
}

//=============================================================================
// Protocol instance
//=============================================================================

STATIC EFI_DPC_PROTOCOL  mMockDpcProtocol = {
  MockDpcQueueDpc,
  MockDpcDispatchDpc
};

//
// Internal reset -- registered with MockProtocolRegisterReset
//

STATIC
VOID
EFIAPI
ResetState (
  VOID
  )
{
  mDpcHead              = 0;
  mDpcTail              = 0;
  mDpcCount             = 0;
  mInsideDispatch       = FALSE;
  mMockDpcQueueCount    = 0;
  mMockDpcDispatchCount = 0;
  ZeroMem (mDpcQueue, sizeof (mDpcQueue));
}

//=============================================================================
// Test-only helpers — NOT part of the protocol interface.
// Fuzz harnesses should NOT call these directly.
//=============================================================================

UINT32
EFIAPI
MockDpcGetQueueCount (
  VOID
  )
{
  return mMockDpcQueueCount;
}

UINT32
EFIAPI
MockDpcGetDispatchCount (
  VOID
  )
{
  return mMockDpcDispatchCount;
}

UINT32
EFIAPI
MockDpcGetPendingCount (
  VOID
  )
{
  return mDpcCount;
}

UINT32
EFIAPI
MockDpcDispatchAll (
  VOID
  )
{
  return MockDpcDrainQueue ();
}

//=============================================================================
// Constructor — install on gFuzzHandle
//=============================================================================

RETURN_STATUS
EFIAPI
MockgEfiDpcProtocolGuidConstructor (
  VOID
  )
{
  EFI_STATUS  Status;

  if ((gBS == NULL) || (gFuzzHandle == NULL)) {
    DEBUG ((DEBUG_WARN, "MockgEfiDpcProtocolGuid: gBS or gFuzzHandle NULL — skipping install\n"));
    return RETURN_SUCCESS;
  }

  DEBUG ((DEBUG_INFO, "MockgEfiDpcProtocolGuid: Constructor\n"));

  //
  // Reset internal state and register for inter-iteration resets
  //
  ResetState ();
  MockProtocolRegisterReset (ResetState);

  Status = gBS->InstallProtocolInterface (
                  &gFuzzHandle,
                  &gEfiDpcProtocolGuid,
                  EFI_NATIVE_INTERFACE,
                  &mMockDpcProtocol
                  );

  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, "MockgEfiDpcProtocolGuid: Install FAILED: %r\n", Status));
    return RETURN_DEVICE_ERROR;
  }

  DEBUG ((DEBUG_INFO, "MockgEfiDpcProtocolGuid: Install on gFuzzHandle: %r\n", Status));
  return RETURN_SUCCESS;
}
