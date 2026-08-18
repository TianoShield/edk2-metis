/** @file
  FuzzContextLib — Single fuzz byte pool implementation.

  Owns the process-lifetime MOCK_FUZZ_CONTEXT (gFuzzPool).  All consume
  helpers are real (non-inline) functions so every compilation unit
  resolves to the same definition — no duplicated static-inline copies.

  Copyright (c) 2026, HBFAplus Contributors. All rights reserved.
  SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include <Uefi.h>
#include <Library/BaseMemoryLib.h>
#include <Library/DebugLib.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Library/FuzzContextLib.h>

//=============================================================================
// The single global fuzz byte pool
//=============================================================================

STATIC MOCK_FUZZ_CONTEXT  gFuzzPool;

//=============================================================================
// Pool Accessor
//=============================================================================

/**
  Return a pointer to the single global fuzz byte pool.

  @return Pointer to the global MOCK_FUZZ_CONTEXT (never NULL).
**/
MOCK_FUZZ_CONTEXT *
EFIAPI
MockFuzzContextGetPool (
  VOID
  )
{
  return &gFuzzPool;
}

//=============================================================================
// Context Lifecycle
//=============================================================================

VOID
EFIAPI
MockFuzzContextInit (
  OUT MOCK_FUZZ_CONTEXT  *Ctx,
  IN  UINT8              *Buffer,
  IN  UINTN              Size
  )
{
  if (Ctx == NULL) {
    return;
  }

  Ctx->Buffer          = Buffer;
  Ctx->Size            = Size;
  Ctx->Offset          = 0;
  Ctx->Limit           = 0;
  Ctx->Exhausted       = (Buffer == NULL || Size == 0);
  Ctx->TimerAdvanceFn  = NULL;
  Ctx->AdvanceInProgress = FALSE;

  DEBUG ((DEBUG_INFO, "MockFuzzContext: Init Buffer=%p Size=%u\n", Buffer, (UINT32)Size));
}

VOID
EFIAPI
MockFuzzContextReset (
  IN OUT MOCK_FUZZ_CONTEXT  *Ctx
  )
{
  if (Ctx == NULL) {
    return;
  }

  Ctx->Offset    = 0;
  Ctx->Limit     = 0;
  Ctx->Exhausted = (Ctx->Buffer == NULL || Ctx->Size == 0);

  //
  // Clear all protocol-specific overrides so the next iteration starts
  // with a clean registry.  This is important in persistent/loop modes
  // where Reset is called between iterations.
  //
  MockFuzzContextClearAllProtocolContexts ();

  DEBUG ((DEBUG_INFO, "MockFuzzContext: Reset, Size=%u\n", (UINT32)Ctx->Size));
}

//=============================================================================
// Byte Consumption
//=============================================================================

UINTN
EFIAPI
MockFuzzContextRemaining (
  IN MOCK_FUZZ_CONTEXT  *Ctx
  )
{
  UINTN  EffectiveEnd;

  if (Ctx == NULL || Ctx->Exhausted) {
    return 0;
  }

  //
  // When a Limit is active, the effective buffer end is the lesser of
  // Size and Limit.  This confines consumption to the bootstrap region
  // (or any other caller-imposed ceiling).
  //
  EffectiveEnd = Ctx->Size;
  if (Ctx->Limit > 0 && Ctx->Limit < EffectiveEnd) {
    EffectiveEnd = Ctx->Limit;
  }

  if (Ctx->Offset >= EffectiveEnd) {
    return 0;
  }

  return EffectiveEnd - Ctx->Offset;
}

UINT8 *
EFIAPI
MockFuzzContextConsume (
  IN OUT MOCK_FUZZ_CONTEXT  *Ctx,
  IN     UINTN              Count
  )
{
  UINT8  *Result;
  UINTN  EffectiveEnd;

  if (Ctx == NULL || Ctx->Exhausted) {
    DEBUG ((DEBUG_VERBOSE, "MockFuzzContext: Consume(%u) - context exhausted\n", (UINT32)Count));
    return NULL;
  }

  //
  // Compute the effective buffer ceiling, honouring any active Limit.
  //
  EffectiveEnd = Ctx->Size;
  if (Ctx->Limit > 0 && Ctx->Limit < EffectiveEnd) {
    EffectiveEnd = Ctx->Limit;
  }

  //
  // AUDIT: Overflow-safe bounds check.  The naive comparison
  //   Offset + Count > EffectiveEnd
  // can wrap around when Count is very large (UINTN), producing a
  // false "in bounds" result and a buffer over-read.  We split the
  // check into two parts that never overflow:
  //   1. Offset already past the ceiling  →  fail
  //   2. Count exceeds the gap            →  fail
  //
  // Note on Count==0: when Offset==EffectiveEnd, this check passes
  // and we return Buffer+Offset (one past the last byte).  This is
  // safe because callers should never dereference a zero-length
  // region.  CreateSubContext(parent, sub, 0) relies on this path
  // to create an immediately-exhausted sub-context.
  //
  if (Ctx->Offset >= EffectiveEnd || Count > EffectiveEnd - Ctx->Offset) {
    DEBUG ((DEBUG_VERBOSE, "MockFuzzContext: Consume(%u) - insufficient data (have %u)\n",
            (UINT32)Count, (UINT32)(Ctx->Offset < EffectiveEnd ? EffectiveEnd - Ctx->Offset : 0)));
    Ctx->Exhausted = TRUE;
    return NULL;
  }

  DEBUG ((DEBUG_INFO, "[FUZZ] @%u: %u bytes\n", (UINT32)Ctx->Offset, (UINT32)Count));

  Result = Ctx->Buffer + Ctx->Offset;
  Ctx->Offset += Count;

  DEBUG ((DEBUG_VERBOSE, "MockFuzzContext: Consumed %u bytes, offset now %u/%u\n",
          (UINT32)Count, (UINT32)Ctx->Offset, (UINT32)EffectiveEnd));

  return Result;
}

UINT8
EFIAPI
MockFuzzContextGetU8 (
  IN OUT MOCK_FUZZ_CONTEXT  *Ctx
  )
{
  UINT8  *Data;
  UINT8  Value;

  Data = MockFuzzContextConsume (Ctx, sizeof (UINT8));
  Value = (Data != NULL) ? *Data : 0;

  DEBUG ((DEBUG_VERBOSE, "MockFuzzContext: GetU8() = 0x%02x\n", Value));
  return Value;
}

UINT16
EFIAPI
MockFuzzContextGetU16 (
  IN OUT MOCK_FUZZ_CONTEXT  *Ctx
  )
{
  UINT8   *Data;
  UINT16  Value;

  Data = MockFuzzContextConsume (Ctx, sizeof (UINT16));
  Value = (Data != NULL) ? (UINT16)(Data[0] | (Data[1] << 8)) : 0;

  DEBUG ((DEBUG_VERBOSE, "MockFuzzContext: GetU16() = 0x%04x\n", Value));
  return Value;
}

UINT32
EFIAPI
MockFuzzContextGetU32 (
  IN OUT MOCK_FUZZ_CONTEXT  *Ctx
  )
{
  UINT8   *Data;
  UINT32  Value;

  Data = MockFuzzContextConsume (Ctx, sizeof (UINT32));
  //
  // AUDIT: All bytes are explicitly cast to UINT32 before shifting.
  // Without the cast, Data[3] (UINT8) is integer-promoted to signed
  // int, and  (int)Data[3] << 24  is undefined behavior when
  // Data[3] >= 0x80 because it shifts a 1 into the sign bit of a
  // 32-bit signed integer (C11 §6.5.7¶4).
  //
  Value = (Data != NULL) ?
          ((UINT32)Data[0] | ((UINT32)Data[1] << 8) |
           ((UINT32)Data[2] << 16) | ((UINT32)Data[3] << 24)) : 0;

  DEBUG ((DEBUG_VERBOSE, "MockFuzzContext: GetU32() = 0x%08x\n", Value));
  return Value;
}

UINT8 *
EFIAPI
MockFuzzContextPeek (
  IN MOCK_FUZZ_CONTEXT  *Ctx,
  IN UINTN              Offset
  )
{
  UINTN  EffectiveEnd;

  if (Ctx == NULL || Ctx->Exhausted) {
    return NULL;
  }

  //
  // Honour the soft limit for peek as well — peeking beyond the limit
  // boundary would leak information about the harness-payload region.
  //
  EffectiveEnd = Ctx->Size;
  if (Ctx->Limit > 0 && Ctx->Limit < EffectiveEnd) {
    EffectiveEnd = Ctx->Limit;
  }

  //
  // AUDIT: Overflow-safe bounds check, same reasoning as Consume.
  // Naive  (Ctx->Offset + Offset >= EffectiveEnd)  can wrap on
  // 32-bit UINTN (or contrived 64-bit values).
  //
  if (Ctx->Offset >= EffectiveEnd || Offset >= EffectiveEnd - Ctx->Offset) {
    return NULL;
  }

  return Ctx->Buffer + Ctx->Offset + Offset;
}

//=============================================================================
// Time Advance
//=============================================================================

VOID
EFIAPI
MockFuzzContextAdvanceTime (
  IN OUT MOCK_FUZZ_CONTEXT  *Ctx
  )
{
  if (Ctx == NULL) {
    return;
  }

  //
  // Re-entrancy guard: if we're already inside an AdvanceTime call for this
  // context (e.g. CoreRestoreTpl auto-advance fired while a timer callback
  // was executing), skip to avoid consuming fuzz data twice or infinite
  // recursion.
  //
  if (Ctx->AdvanceInProgress) {
    return;
  }

  if (Ctx->TimerAdvanceFn == NULL) {
    return;
  }

  Ctx->AdvanceInProgress = TRUE;

  //
  // Consume a UINT16 and scale by 100 to get 0–6,553,500 µs (~6.5s).
  // On exhaustion, advance by a default 200ms (one TCP tick interval).
  // This calls CoreTimerTick → mEfiCheckTimerEvent → CoreCheckTimers
  // → expired timer callbacks dispatch — the same path that real edk2
  // hardware timer interrupts take.
  //
  {
    UINT64  TimeDeltaUs;

    if (MockFuzzContextRemaining (Ctx) >= sizeof (UINT16)) {
      TimeDeltaUs = (UINT64)MockFuzzContextGetU16 (Ctx) * 100;
    } else {
      TimeDeltaUs = 200000;  // 200ms default — one TCP tick
    }

    if (TimeDeltaUs > 0) {
      DEBUG ((DEBUG_VERBOSE, "MockFuzzContext: AdvanceTime by %lu us\n",
              TimeDeltaUs));
      Ctx->TimerAdvanceFn (TimeDeltaUs);
    }
  }

  Ctx->AdvanceInProgress = FALSE;
}

//=============================================================================
// Bootstrap Region — Limit / Advance / Sub-Context
//=============================================================================

/**
  Set a soft consumption limit on a fuzz context.

  While a limit is active, Consume / Remaining / GetU* / Peek treat
  MIN(Size, Limit) as the effective buffer end.

  @param[in,out] Ctx    Context to constrain.
  @param[in]     Limit  Byte offset ceiling (absolute).
**/
VOID
EFIAPI
MockFuzzContextSetLimit (
  IN OUT MOCK_FUZZ_CONTEXT  *Ctx,
  IN     UINTN              Limit
  )
{
  if (Ctx == NULL) {
    return;
  }

  Ctx->Limit = Limit;

  DEBUG ((DEBUG_INFO, "MockFuzzContext: SetLimit=%u (Size=%u)\n",
          (UINT32)Limit, (UINT32)Ctx->Size));
}

/**
  Remove the soft consumption limit, restoring full-buffer access.

  @param[in,out] Ctx  Context to unconstrain.
**/
VOID
EFIAPI
MockFuzzContextClearLimit (
  IN OUT MOCK_FUZZ_CONTEXT  *Ctx
  )
{
  if (Ctx == NULL) {
    return;
  }

  Ctx->Limit = 0;

  //
  // Clearing the limit may make bytes available again if the context
  // was previously exhausted only because of the limit ceiling.
  //
  if (Ctx->Exhausted && Ctx->Buffer != NULL && Ctx->Offset < Ctx->Size) {
    Ctx->Exhausted = FALSE;
  }

  DEBUG ((DEBUG_INFO, "MockFuzzContext: ClearLimit (Size=%u, Offset=%u)\n",
          (UINT32)Ctx->Size, (UINT32)Ctx->Offset));
}

/**
  Advance the consumption offset to an absolute position.

  If Offset is already at or past Target, this is a no-op.  Clears the
  Exhausted flag when the advance succeeds and bytes remain after Target.

  @param[in,out] Ctx     Context to advance.
  @param[in]     Target  Absolute byte offset to move to.
**/
VOID
EFIAPI
MockFuzzContextAdvanceTo (
  IN OUT MOCK_FUZZ_CONTEXT  *Ctx,
  IN     UINTN              Target
  )
{
  if (Ctx == NULL) {
    return;
  }

  //
  // Do not move backwards — AdvanceTo is a forward-only skip.
  //
  if (Target <= Ctx->Offset) {
    DEBUG ((DEBUG_VERBOSE, "MockFuzzContext: AdvanceTo(%u) - already at %u, no-op\n",
            (UINT32)Target, (UINT32)Ctx->Offset));
    return;
  }

  //
  // Clamp to Size so we never point past the physical buffer.
  // NOTE: AdvanceTo intentionally does NOT clamp to Ctx->Limit.
  // This allows bootstrap→payload transitions where AdvanceTo skips
  // past a limited bootstrap region to reach the payload area.
  //
  if (Target > Ctx->Size) {
    Target = Ctx->Size;
  }

  DEBUG ((DEBUG_INFO, "MockFuzzContext: AdvanceTo %u -> %u (Size=%u)\n",
          (UINT32)Ctx->Offset, (UINT32)Target, (UINT32)Ctx->Size));

  Ctx->Offset = Target;

  //
  // Re-evaluate exhaustion based on the new offset.
  //
  Ctx->Exhausted = (Ctx->Buffer == NULL || Ctx->Offset >= Ctx->Size);
}

/**
  Carve an independent sub-context from the parent pool.

  Consumes exactly ByteCount bytes from ParentCtx and initializes SubCtx
  to wrap that region.  The sub-context has its own Offset (starting at 0)
  and Size (= ByteCount), so consumers reading from it do not touch the
  parent's cursor.

  @param[in,out] ParentCtx  Pool to carve from.
  @param[out]    SubCtx     Receives the carved sub-context.
  @param[in]     ByteCount  Number of bytes to carve.

  @retval EFI_SUCCESS            SubCtx is ready for use.
  @retval EFI_OUT_OF_RESOURCES   Not enough bytes in ParentCtx.
  @retval EFI_INVALID_PARAMETER  ParentCtx or SubCtx is NULL.
**/
EFI_STATUS
EFIAPI
MockFuzzContextCreateSubContext (
  IN OUT MOCK_FUZZ_CONTEXT  *ParentCtx,
  OUT    MOCK_FUZZ_CONTEXT  *SubCtx,
  IN     UINTN              ByteCount
  )
{
  UINT8  *Region;

  if (ParentCtx == NULL || SubCtx == NULL) {
    return EFI_INVALID_PARAMETER;
  }

  //
  // Consume ByteCount bytes from the parent pool.  Consume respects the
  // parent's Limit, so a bootstrap limit will correctly bound sub-context
  // carving.
  //
  Region = MockFuzzContextConsume (ParentCtx, ByteCount);
  if (Region == NULL) {
    //
    // Not enough bytes.  Initialize SubCtx as exhausted so downstream
    // consumers degrade gracefully.
    //
    ZeroMem (SubCtx, sizeof (*SubCtx));
    SubCtx->Exhausted = TRUE;

    DEBUG ((DEBUG_WARN, "MockFuzzContext: CreateSubContext(%u) - insufficient data\n",
            (UINT32)ByteCount));
    return EFI_OUT_OF_RESOURCES;
  }

  //
  // Initialize the sub-context as a standalone buffer wrapping the carved
  // region.  Limit = 0 (no limit), PumpEvents empty.
  //
  ZeroMem (SubCtx, sizeof (*SubCtx));
  SubCtx->Buffer    = Region;
  SubCtx->Size      = ByteCount;
  SubCtx->Offset    = 0;
  SubCtx->Exhausted = (ByteCount == 0);

  DEBUG ((DEBUG_INFO, "MockFuzzContext: Created SubContext Buffer=%p Size=%u\n",
          Region, (UINT32)ByteCount));

  return EFI_SUCCESS;
}

//=============================================================================
// Protocol Context Registry
//=============================================================================
//
// A small, fixed-size lookup table mapping EFI_GUID → MOCK_FUZZ_CONTEXT*.
// Harnesses register overrides before InitializeHarness so that mock
// protocols receive their dedicated byte regions instead of the global pool.
//
// Linear scan is fine — max 16 entries, called once per mock constructor.
//

///
/// Single entry in the protocol context registry.
///
typedef struct {
  EFI_GUID            Guid;         ///< Protocol GUID (copied, not pointed)
  MOCK_FUZZ_CONTEXT   *Context;     ///< Override context (NULL = slot empty)
} MOCK_FUZZ_PROTOCOL_CTX_ENTRY;

///
/// Global protocol context registry table.
///
STATIC MOCK_FUZZ_PROTOCOL_CTX_ENTRY  gProtocolCtxTable[MOCK_FUZZ_MAX_PROTOCOL_CTXS];

///
/// Number of active entries in the registry.
///
STATIC UINTN  gProtocolCtxCount = 0;

//
// Forward declaration -- SetProtocolContext delegates to Clear when
// OverrideCtx is NULL.
//
EFI_STATUS
EFIAPI
MockFuzzContextClearProtocolContext (
  IN CONST EFI_GUID  *ProtocolGuid
  );

/**
  Register or clear a protocol-specific fuzz context override.

  When OverrideCtx is non-NULL, the context is stored (or updated) in the
  per-protocol registry.  When OverrideCtx is NULL, any existing override
  for this GUID is removed (equivalent to ClearProtocolContext).

  @param[in] ProtocolGuid  GUID identifying the protocol to override.
  @param[in] OverrideCtx   Fuzz context the mock should use, or NULL to
                           remove any existing override for this GUID.

  @retval EFI_SUCCESS            Registered, updated, or removed.
  @retval EFI_INVALID_PARAMETER  ProtocolGuid is NULL.
  @retval EFI_OUT_OF_RESOURCES   Table full and GUID not already present.
**/
EFI_STATUS
EFIAPI
MockFuzzContextSetProtocolContext (
  IN CONST EFI_GUID          *ProtocolGuid,
  IN       MOCK_FUZZ_CONTEXT *OverrideCtx  OPTIONAL
  )
{
  UINTN  Index;

  if (ProtocolGuid == NULL) {
    return EFI_INVALID_PARAMETER;
  }

  //
  // NULL context means "remove the override".  Delegate to Clear so that
  // callers can use   SetProtocolContext (GUID, NULL)   as shorthand for
  // ClearProtocolContext (GUID).
  //
  if (OverrideCtx == NULL) {
    return MockFuzzContextClearProtocolContext (ProtocolGuid);
  }

  //
  // Update existing entry if GUID is already registered.
  //
  for (Index = 0; Index < gProtocolCtxCount; Index++) {
    if (CompareGuid (&gProtocolCtxTable[Index].Guid, ProtocolGuid)) {
      gProtocolCtxTable[Index].Context = OverrideCtx;
      DEBUG ((DEBUG_INFO, "MockFuzzContext: Updated protocol context at slot %u\n",
              (UINT32)Index));
      return EFI_SUCCESS;
    }
  }

  if (gProtocolCtxCount >= MOCK_FUZZ_MAX_PROTOCOL_CTXS) {
    DEBUG ((DEBUG_ERROR, "MockFuzzContext: Protocol context table full (%u)\n",
            MOCK_FUZZ_MAX_PROTOCOL_CTXS));
    return EFI_OUT_OF_RESOURCES;
  }

  CopyGuid (&gProtocolCtxTable[gProtocolCtxCount].Guid, ProtocolGuid);
  gProtocolCtxTable[gProtocolCtxCount].Context = OverrideCtx;
  gProtocolCtxCount++;

  DEBUG ((DEBUG_INFO, "MockFuzzContext: Registered protocol context at slot %u\n",
          (UINT32)(gProtocolCtxCount - 1)));

  return EFI_SUCCESS;
}

/**
  Look up a protocol-specific fuzz context override.

  @param[in] ProtocolGuid  GUID to look up.

  @return  Override context, or NULL if none registered.
**/
MOCK_FUZZ_CONTEXT *
EFIAPI
MockFuzzContextGetProtocolContext (
  IN CONST EFI_GUID  *ProtocolGuid
  )
{
  UINTN  Index;

  if (ProtocolGuid == NULL) {
    return NULL;
  }

  for (Index = 0; Index < gProtocolCtxCount; Index++) {
    if (CompareGuid (&gProtocolCtxTable[Index].Guid, ProtocolGuid)) {
      return gProtocolCtxTable[Index].Context;
    }
  }

  return NULL;
}

/**
  Remove a single protocol context override.

  @param[in] ProtocolGuid  GUID whose override should be removed.

  @retval EFI_SUCCESS    Removed.
  @retval EFI_NOT_FOUND  No override was registered for this GUID.
**/
EFI_STATUS
EFIAPI
MockFuzzContextClearProtocolContext (
  IN CONST EFI_GUID  *ProtocolGuid
  )
{
  UINTN  Index;

  if (ProtocolGuid == NULL) {
    return EFI_INVALID_PARAMETER;
  }

  for (Index = 0; Index < gProtocolCtxCount; Index++) {
    if (CompareGuid (&gProtocolCtxTable[Index].Guid, ProtocolGuid)) {
      //
      // Compact by shifting the last entry into the removed slot.
      // Order does not matter for a linear-scan table.
      //
      gProtocolCtxCount--;
      if (Index < gProtocolCtxCount) {
        CopyGuid (&gProtocolCtxTable[Index].Guid,
                   &gProtocolCtxTable[gProtocolCtxCount].Guid);
        gProtocolCtxTable[Index].Context =
          gProtocolCtxTable[gProtocolCtxCount].Context;
      }

      ZeroMem (&gProtocolCtxTable[gProtocolCtxCount],
               sizeof (gProtocolCtxTable[gProtocolCtxCount]));

      DEBUG ((DEBUG_INFO, "MockFuzzContext: Cleared protocol context from slot %u\n",
              (UINT32)Index));
      return EFI_SUCCESS;
    }
  }

  return EFI_NOT_FOUND;
}

/**
  Remove all protocol context overrides.

  Called during MockFuzzContextReset() to ensure a clean slate for each
  fuzz iteration.
**/
VOID
EFIAPI
MockFuzzContextClearAllProtocolContexts (
  VOID
  )
{
  if (gProtocolCtxCount == 0) {
    return;
  }

  DEBUG ((DEBUG_INFO, "MockFuzzContext: Clearing all %u protocol contexts\n",
          (UINT32)gProtocolCtxCount));

  ZeroMem (gProtocolCtxTable, sizeof (gProtocolCtxTable));
  gProtocolCtxCount = 0;
}

//=============================================================================
// Mock Protocol Reset Registry
//=============================================================================

STATIC MOCK_PROTOCOL_RESET_FN  gResetRegistry[MOCK_PROTOCOL_MAX_RESET_SLOTS];
STATIC UINTN                   gResetRegistryCount = 0;

EFI_STATUS
EFIAPI
MockProtocolRegisterReset (
  IN MOCK_PROTOCOL_RESET_FN  ResetFn
  )
{
  UINTN  Index;

  if (ResetFn == NULL) {
    return EFI_INVALID_PARAMETER;
  }

  for (Index = 0; Index < gResetRegistryCount; Index++) {
    if (gResetRegistry[Index] == ResetFn) {
      return EFI_ALREADY_STARTED;
    }
  }

  if (gResetRegistryCount >= MOCK_PROTOCOL_MAX_RESET_SLOTS) {
    return EFI_OUT_OF_RESOURCES;
  }

  gResetRegistry[gResetRegistryCount] = ResetFn;
  gResetRegistryCount++;
  return EFI_SUCCESS;
}

VOID
EFIAPI
MockProtocolResetAll (
  VOID
  )
{
  UINTN  Index;

  for (Index = 0; Index < gResetRegistryCount; Index++) {
    if (gResetRegistry[Index] != NULL) {
      gResetRegistry[Index] ();
    }
  }

  MockFuzzContextClearAllProtocolContexts ();
}

VOID
EFIAPI
MockProtocolClearResetRegistry (
  VOID
  )
{
  ZeroMem (gResetRegistry, sizeof (gResetRegistry));
  gResetRegistryCount = 0;
}