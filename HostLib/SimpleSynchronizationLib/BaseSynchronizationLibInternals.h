/** @file
  Declaration of internal functions in BaseSynchronizationLib.

  Copyright (c) 2006 - 2010, Intel Corporation. All rights reserved.<BR>
  SPDX-License-Identifier: BSD-2-Clause-Patent

**/

//
// ============================================================================
// HBFAplus HOST-BASED REHOSTING AUDIT
// ============================================================================
//
// File   : BaseSynchronizationLibInternals.h
// Role   : Declares Internal* helper functions for the SimpleSynchronizationLib.
// Origin : Derived from edk2 MdePkg/Library/BaseSynchronizationLib.
//
// Differences from edk2 upstream:
//   1. TimerLib.h include REMOVED — host environment does not need
//      performance counter for spin-lock timeout.
//   2. InternalGetSpinLockProperties() declaration REMOVED — replaced by
//      hardcoded return 32 in GetSpinLockProperties(), acceptable for host.
//   3. InternalSyncCompareExchange16() declaration was MISSING — ADDED by
//      this audit to support any edk2 caller using the 16-bit CAS API.
//
// Rehosting assessment:
//   - Correct: all 4 original internal declarations match edk2 signatures.
//   - Fixed: added InternalSyncCompareExchange16 for completeness.
//   - No TimerLib needed → eliminates host-environment dependency.
//
// Fuzzing assessment:
//   - These internal functions use real x86 atomic instructions on host,
//     which is safe and deterministic for single-threaded fuzzing.
//   - No fuzz-data dependency; purely structural support.
// ============================================================================
//

#ifndef __BASE_SYNCHRONIZATION_LIB_INTERNALS__
#define __BASE_SYNCHRONIZATION_LIB_INTERNALS__

#include <Base.h>
#include <Library/SynchronizationLib.h>
#include <Library/BaseLib.h>
#include <Library/DebugLib.h>
#include <Library/PcdLib.h>

/**
  Performs an atomic increment of an 32-bit unsigned integer.

  Performs an atomic increment of the 32-bit unsigned integer specified by
  Value and returns the incremented value. The increment operation must be
  performed using MP safe mechanisms. The state of the return value is not
  guaranteed to be MP safe.

  @param  Value A pointer to the 32-bit value to increment.

  @return The incremented value.

**/
UINT32
EFIAPI
InternalSyncIncrement (
  IN      volatile UINT32           *Value
  );


/**
  Performs an atomic decrement of an 32-bit unsigned integer.

  Performs an atomic decrement of the 32-bit unsigned integer specified by
  Value and returns the decrement value. The decrement operation must be
  performed using MP safe mechanisms. The state of the return value is not
  guaranteed to be MP safe.

  @param  Value A pointer to the 32-bit value to decrement.

  @return The decrement value.

**/
UINT32
EFIAPI
InternalSyncDecrement (
  IN      volatile UINT32           *Value
  );


/**
  Performs an atomic compare exchange operation on a 16-bit unsigned integer.

  Performs an atomic compare exchange operation on the 16-bit unsigned integer
  specified by Value.  If Value is equal to CompareValue, then Value is set to
  ExchangeValue and CompareValue is returned.  If Value is not equal to
  CompareValue, then Value is returned.  The compare exchange operation must be
  performed using MP safe mechanisms.

  @param  Value         A pointer to the 16-bit value for the compare exchange
                        operation.
  @param  CompareValue  A 16-bit value used in compare operation.
  @param  ExchangeValue A 16-bit value used in exchange operation.

  @return The original *Value before exchange.

**/
UINT16
EFIAPI
InternalSyncCompareExchange16 (
  IN      volatile UINT16           *Value,
  IN      UINT16                    CompareValue,
  IN      UINT16                    ExchangeValue
  );


/**
  Performs an atomic compare exchange operation on a 32-bit unsigned integer.

  Performs an atomic compare exchange operation on the 32-bit unsigned integer
  specified by Value.  If Value is equal to CompareValue, then Value is set to
  ExchangeValue and CompareValue is returned.  If Value is not equal to CompareValue,
  then Value is returned.  The compare exchange operation must be performed using
  MP safe mechanisms.

  @param  Value         A pointer to the 32-bit value for the compare exchange
                        operation.
  @param  CompareValue  A 32-bit value used in compare operation.
  @param  ExchangeValue A 32-bit value used in exchange operation.

  @return The original *Value before exchange.

**/
UINT32
EFIAPI
InternalSyncCompareExchange32 (
  IN      volatile UINT32           *Value,
  IN      UINT32                    CompareValue,
  IN      UINT32                    ExchangeValue
  );


/**
  Performs an atomic compare exchange operation on a 64-bit unsigned integer.

  Performs an atomic compare exchange operation on the 64-bit unsigned integer specified
  by Value.  If Value is equal to CompareValue, then Value is set to ExchangeValue and
  CompareValue is returned.  If Value is not equal to CompareValue, then Value is returned.
  The compare exchange operation must be performed using MP safe mechanisms.

  @param  Value         A pointer to the 64-bit value for the compare exchange
                        operation.
  @param  CompareValue  A 64-bit value used in compare operation.
  @param  ExchangeValue A 64-bit value used in exchange operation.

  @return The original *Value before exchange.

**/
UINT64
EFIAPI
InternalSyncCompareExchange64 (
  IN      volatile UINT64           *Value,
  IN      UINT64                    CompareValue,
  IN      UINT64                    ExchangeValue
  );

#endif
