/** @file
  FuzzContextLib - Single fuzz byte pool for the entire HBFAplus process.

  Owns ONE global MOCK_FUZZ_CONTEXT (the "pool").  ToolChainHarnessLib calls
  MockFuzzContextInit() on the pool once per iteration to load the
  fuzzer-supplied bytes.  Every consumer — harness API selectors, mock
  protocol functions, MMIO/Port-I/O/MSR intercepts — calls the Consume /
  GetU8 / GetU16 / GetU32 helpers to pull bytes from the same pool.

  The pool object is a process-lifetime static; MockFuzzContextGetPool()
  returns its address.  Mock library constructors call it during
  ProcessLibraryConstructorList() to store the pointer for later use.

  Copyright (c) 2026, HBFAplus Contributors. All rights reserved.
  SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#ifndef _FUZZ_CONTEXT_LIB_H_
#define _FUZZ_CONTEXT_LIB_H_

#include <Uefi.h>

//=============================================================================
// Protocol Context Registry Configuration
//=============================================================================

///
/// Maximum number of protocol-specific context overrides that can be
/// registered simultaneously.  Each harness that needs to steer mock
/// fuzz bytes through a particular protocol GUID registers an entry;
/// 1024 slots is generous for even the most complex driver graphs.
///
#define MOCK_FUZZ_MAX_PROTOCOL_CTXS  1024

//=============================================================================
// Fuzz Context Structure
//=============================================================================

///
/// Callback for advancing simulated time.
///
/// MockFuzzContextAdvanceTime consumes a fuzz-derived UINT16, scales it
/// to microseconds, and calls this function so that timer events
/// (e.g. TCP heartbeat) can fire via the real DXE Core timer machinery.
///
typedef VOID (EFIAPI *MOCK_TIMER_ADVANCE_FN)(IN UINT64 Microseconds);

///
/// Shared fuzz buffer context — loaded per iteration, consumed by everyone.
///
/// The struct owns two concerns:
///   1. Fuzz buffer consumption (Buffer / Size / Offset / Exhausted).
///   2. Timer advance callback (TimerAdvanceFn).
///
typedef struct {
  //
  // ---- Fuzz buffer fields ----
  //
  UINT8   *Buffer;      ///< Pointer to fuzz input buffer
  UINTN   Size;         ///< Total size of buffer
  UINTN   Offset;       ///< Current consumption offset
  BOOLEAN Exhausted;    ///< TRUE when no more data available
  UINTN   Limit;        ///< Soft ceiling on consumption (0 = no limit).
                         ///< When non-zero, Consume/Remaining/GetU*/Peek
                         ///< treat MIN(Size, Limit) as the effective end.

  //
  // ---- Timer advance callback ----
  //
  MOCK_TIMER_ADVANCE_FN  TimerAdvanceFn;  ///< Optional: called by AdvanceTime
                                           ///< to advance simulated time.
                                           ///< Set by MockTimerInit().

  //
  // ---- AdvanceTime re-entrancy guard ----
  //
  BOOLEAN  AdvanceInProgress;  ///< TRUE while MockFuzzContextAdvanceTime is
                                ///< executing.  Checked by CoreRestoreTpl's
                                ///< auto-advance to prevent recursive calls.
} MOCK_FUZZ_CONTEXT;

//=============================================================================
// Pool Accessor
//=============================================================================

/**
  Return a pointer to the single global fuzz byte pool.

  The pool is a process-lifetime static with stable address.  Mock library
  constructors call this to store the pointer; ToolChainHarnessLib calls it
  once before ProcessLibraryConstructorList() so that the harness-level
  pointer is established before any constructors run.

  @return Pointer to the global MOCK_FUZZ_CONTEXT (never NULL).
**/
MOCK_FUZZ_CONTEXT *
EFIAPI
MockFuzzContextGetPool (
  VOID
  );

//=============================================================================
// Context Lifecycle
//=============================================================================

/**
  Initialize a fuzz context with the given buffer.

  @param[out] Ctx     Context to initialize.
  @param[in]  Buffer  Pointer to fuzz input buffer.
  @param[in]  Size    Size of buffer in bytes.
**/
VOID
EFIAPI
MockFuzzContextInit (
  OUT MOCK_FUZZ_CONTEXT  *Ctx,
  IN  UINT8              *Buffer,
  IN  UINTN              Size
  );

/**
  Reset context offset to 0 (rewind for next iteration).

  @param[in,out] Ctx  Context to reset.
**/
VOID
EFIAPI
MockFuzzContextReset (
  IN OUT MOCK_FUZZ_CONTEXT  *Ctx
  );

//=============================================================================
// Byte Consumption
//=============================================================================

/**
  Return the number of unconsumed bytes remaining in the context.

  @param[in]  Ctx  Context to query.

  @return Number of remaining bytes, or 0 if NULL/exhausted.
**/
UINTN
EFIAPI
MockFuzzContextRemaining (
  IN MOCK_FUZZ_CONTEXT  *Ctx
  );

/**
  Consume N bytes from the context.

  @param[in,out] Ctx    Context to consume from.
  @param[in]     Count  Number of bytes to consume.

  @return Pointer to the consumed bytes, or NULL if insufficient data.
**/
UINT8 *
EFIAPI
MockFuzzContextConsume (
  IN OUT MOCK_FUZZ_CONTEXT  *Ctx,
  IN     UINTN              Count
  );

/**
  Consume one UINT8 from the context.

  @param[in,out] Ctx  Context to consume from.

  @return UINT8 value, or 0 if exhausted.
**/
UINT8
EFIAPI
MockFuzzContextGetU8 (
  IN OUT MOCK_FUZZ_CONTEXT  *Ctx
  );

/**
  Consume one UINT16 (little-endian) from the context.

  @param[in,out] Ctx  Context to consume from.

  @return UINT16 value, or 0 if exhausted.
**/
UINT16
EFIAPI
MockFuzzContextGetU16 (
  IN OUT MOCK_FUZZ_CONTEXT  *Ctx
  );

/**
  Consume one UINT32 (little-endian) from the context.

  @param[in,out] Ctx  Context to consume from.

  @return UINT32 value, or 0 if exhausted.
**/
UINT32
EFIAPI
MockFuzzContextGetU32 (
  IN OUT MOCK_FUZZ_CONTEXT  *Ctx
  );

/**
  Peek at a byte at the given offset from the current position without
  consuming it.

  @param[in]  Ctx     Context to peek into.
  @param[in]  Offset  Offset from current position.

  @return Pointer to the byte, or NULL if out of bounds.
**/
UINT8 *
EFIAPI
MockFuzzContextPeek (
  IN MOCK_FUZZ_CONTEXT  *Ctx,
  IN UINTN              Offset
  );

//=============================================================================
// Time Advance
//=============================================================================

/**
  Advance simulated time using a fuzz-derived delta.

  Consumes one UINT16 from fuzz data, scales by 100 to get microseconds
  (0–6,553,500 us, ~6.5s), and calls TimerAdvanceFn.  This causes
  CoreTimerTick to fire, which signals mEfiCheckTimerEvent, which causes
  CoreCheckTimers to dispatch expired timer callbacks — exactly the path
  real edk2 hardware timer interrupts take.

  When fuzz data is exhausted, advances by a default 200ms (one TCP tick).

  Guards against re-entrancy: if AdvanceTime is already in progress
  (e.g. a timer callback triggers RestoreTpl which auto-advances),
  the call is a no-op.

  @param[in,out] Ctx  Fuzz context.
**/
VOID
EFIAPI
MockFuzzContextAdvanceTime (
  IN OUT MOCK_FUZZ_CONTEXT  *Ctx
  );


//=============================================================================
// Bootstrap Region — Limit / Advance / Sub-Context
//=============================================================================

/**
  Set a soft consumption limit on a fuzz context.

  While a limit is active, Consume / Remaining / GetU* / Peek treat
  MIN(Size, Limit) as the effective buffer end.  This lets
  ToolChainHarnessLib cap the bytes available to bootstrap code
  (constructors + InitializeHarness) so that the harness payload
  starts at a deterministic offset.

  @param[in,out] Ctx    Context to constrain.
  @param[in]     Limit  Byte offset ceiling (absolute, not relative).
                         Must be > 0; pass 0 to remove the limit instead
                         (or call MockFuzzContextClearLimit).
**/
VOID
EFIAPI
MockFuzzContextSetLimit (
  IN OUT MOCK_FUZZ_CONTEXT  *Ctx,
  IN     UINTN              Limit
  );

/**
  Remove the soft consumption limit, restoring full-buffer access.

  @param[in,out] Ctx  Context to unconstrain.
**/
VOID
EFIAPI
MockFuzzContextClearLimit (
  IN OUT MOCK_FUZZ_CONTEXT  *Ctx
  );

/**
  Advance the consumption offset to an absolute position.

  If Offset is already at or past Target, this is a no-op.
  Clears the Exhausted flag when the advance succeeds and there are
  bytes remaining after Target.

  Typical use: after bootstrap code finishes, advance to the bootstrap
  size so the harness payload begins at a fixed, seed-friendly offset.

  @param[in,out] Ctx     Context to advance.
  @param[in]     Target  Absolute byte offset to move to.
**/
VOID
EFIAPI
MockFuzzContextAdvanceTo (
  IN OUT MOCK_FUZZ_CONTEXT  *Ctx,
  IN     UINTN              Target
  );

/**
  Carve an independent sub-context from the parent pool.

  Consumes exactly ByteCount bytes from ParentCtx and initializes
  SubCtx to wrap that region.  The sub-context is a standalone
  MOCK_FUZZ_CONTEXT — its Offset starts at 0 and its Size equals
  ByteCount — so any mock that receives it will consume bytes from
  the carved region without touching the parent's offset.

  If ParentCtx does not have ByteCount bytes remaining (respecting
  any active Limit), the sub-context is initialized as exhausted.

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
  );

//=============================================================================
// Protocol Context Registry
//=============================================================================

/**
  Register a protocol-specific fuzz context override.

  Associates ProtocolGuid with OverrideCtx in a global lookup table.
  When a mock protocol calls MockFuzzContextGetProtocolContext() with
  this GUID, it receives OverrideCtx instead of the global pool.

  This lets a harness pre-allocate a sub-context (via
  MockFuzzContextCreateSubContext) and bind it to a specific protocol,
  giving the harness full control over which bytes each mock consumes.

  @param[in] ProtocolGuid  GUID identifying the protocol to override.
  @param[in] OverrideCtx   Fuzz context the mock should use, or NULL
                           to remove any existing override for this GUID.

  @retval EFI_SUCCESS            Registered, updated, or removed.
  @retval EFI_INVALID_PARAMETER  ProtocolGuid is NULL.
  @retval EFI_OUT_OF_RESOURCES   Registry is full and GUID not already present.
**/
EFI_STATUS
EFIAPI
MockFuzzContextSetProtocolContext (
  IN CONST EFI_GUID         *ProtocolGuid,
  IN       MOCK_FUZZ_CONTEXT  *OverrideCtx  OPTIONAL
  );

/**
  Look up a protocol-specific fuzz context override.

  If ProtocolGuid has a registered override, returns the associated
  MOCK_FUZZ_CONTEXT.  Otherwise returns NULL, signalling the caller
  to fall back to the global pool.

  @param[in] ProtocolGuid  GUID to look up.

  @return  Override context, or NULL if none registered.
**/
MOCK_FUZZ_CONTEXT *
EFIAPI
MockFuzzContextGetProtocolContext (
  IN CONST EFI_GUID  *ProtocolGuid
  );

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
  );

/**
  Remove all protocol context overrides.

  Called during MockFuzzContextReset() to ensure a clean slate for each
  fuzz iteration.
**/
VOID
EFIAPI
MockFuzzContextClearAllProtocolContexts (
  VOID
  );
//=============================================================================
// Mock Protocol Reset Registry
//=============================================================================

///
/// Maximum number of mock protocols that can register a reset callback.
///
#define MOCK_PROTOCOL_MAX_RESET_SLOTS  64

///
/// Callback signature for mock protocol reset functions.
///
typedef VOID (EFIAPI *MOCK_PROTOCOL_RESET_FN)(VOID);

/**
  Register a reset callback for a mock protocol.

  Each mock constructor calls this to register its internal reset function.
  When MockProtocolResetAll() is called (e.g. from test setUp), every
  registered callback is invoked to return mock state to pristine defaults.

  @param[in] ResetFn  The reset function to register.

  @retval EFI_SUCCESS            Registered.
  @retval EFI_INVALID_PARAMETER  ResetFn is NULL.
  @retval EFI_OUT_OF_RESOURCES   Registry is full.
  @retval EFI_ALREADY_STARTED    This exact function pointer is already registered.
**/
EFI_STATUS
EFIAPI
MockProtocolRegisterReset (
  IN MOCK_PROTOCOL_RESET_FN  ResetFn
  );

/**
  Invoke all registered mock protocol reset callbacks.

  Resets every mock to its constructor-time defaults.  Tests call this
  from setUp/teardown instead of individual MockXxxReset() calls.
  Also clears all protocol context overrides.
**/
VOID
EFIAPI
MockProtocolResetAll (
  VOID
  );

/**
  Remove all entries from the reset registry.

  Typically not needed — the registry persists for the process lifetime.
  Provided for completeness and test isolation.
**/
VOID
EFIAPI
MockProtocolClearResetRegistry (
  VOID
  );
#endif // _FUZZ_CONTEXT_LIB_H_
