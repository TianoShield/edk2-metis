/** @file
  UefiRuntimeServicesTableLibHost - Host-based UEFI Runtime Services for
  rehosting and fuzzing.

  AUDIT SUMMARY (UefiRuntimeServicesTableLibHost):
  ================================================
  This library provides a host-environment implementation of the UEFI Runtime
  Services Table (gRT) for use in rehosting UEFI firmware components on Linux
  for fuzzing.

  Implemented RT Services:
    - GetTime          : Returns in-memory time (default: 2025-01-01 00:00:00). (Time.c)
    - SetTime          : Updates in-memory time with range validation. (Time.c)
    - GetWakeupTime    : Returns disabled state. (Time.c)
    - SetWakeupTime    : No-op, returns EFI_SUCCESS. (Time.c)
    - GetVariable      : In-memory variable store via linked list. (OsVariable.c)
    - SetVariable      : In-memory variable store, supports add/delete/append.
                         Auth2 verification disabled (#if 0). (OsVariable.c)
    - GetNextVariableName : Enumerates in-memory variable list. (OsVariable.c)
    - GetNextHighMonotonicCount : Returns incrementing counter. (this file)
    - QueryVariableInfo : Returns virtual storage limits. (OsVariable.c)
    - ResetSystem      : No-op for fuzzing (does not exit). (this file)

  Stubbed RT Services (return EFI_UNSUPPORTED, do NOT crash):
    - SetVirtualAddressMap : Not meaningful on host.
    - ConvertPointer       : Not meaningful on host.
    - UpdateCapsule        : Not meaningful on host.
    - QueryCapsuleCapabilities : Not meaningful on host.

  Design Notes:
    - All stubs return EFI_UNSUPPORTED instead of ASSERT(FALSE) to avoid
      crashing the fuzzer when untested code paths call these services.
    - Variable storage is entirely in-memory (no flash/NV backing).
    - Auth2 PKCS#7 verification is disabled for fuzzing throughput.
    - ResetSystem is a no-op so the fuzzer continues to the next iteration.

Copyright (c) 2018, Intel Corporation. All rights reserved.<BR>
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include <Uefi.h>
#include <Library/DebugLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/UefiBootServicesTableLib.h>

extern EFI_RUNTIME_SERVICES mEfiRuntimeServicesTableTemplate;

EFI_RUNTIME_SERVICES  *gRT         = &mEfiRuntimeServicesTableTemplate;

/**
  Constructor for the host-based Runtime Services Table Library.

  Mirrors upstream UefiRuntimeServicesTableLibConstructor which does:
    gRT = SystemTable->RuntimeServices;

  In the host environment, gRT is already statically initialized to
  &mEfiRuntimeServicesTableTemplate. The constructor validates this and
  wires gST->RuntimeServices = gRT so that code accessing RT through
  the System Table works correctly.

  @retval RETURN_SUCCESS  Always succeeds.
**/
RETURN_STATUS
EFIAPI
UefiRuntimeServicesTableLibConstructor (
  VOID
  )
{
  ASSERT (gRT != NULL);

  //
  // Wire gST->RuntimeServices = gRT if gST is available.
  // This mirrors the upstream behavior where the DXE core sets
  // SystemTable->RuntimeServices before loading any driver.
  //
  if (gST != NULL) {
    gST->RuntimeServices = gRT;
  }

  DEBUG ((DEBUG_INFO, "UefiRuntimeServicesTableLibConstructor: gRT=%p wired to gST\n", gRT));
  return RETURN_SUCCESS;
}

//
// Monotonic counter for GetNextHighMonotonicCount
//
STATIC UINT32 mHighMonotonicCount = 0;

// ============================================================================
// Non-crashing stubs for services not meaningful on host
// ============================================================================

/**
  [AUDIT] Non-crashing stub for unimplemented RT services.
  Unlike the BS lib's CoreEfiNotAvailableYetArgX which calls ASSERT(FALSE),
  this returns EFI_UNSUPPORTED so the fuzzer does not crash when edk2
  components invoke services that have no host-side meaning (e.g.,
  SetVirtualAddressMap, ConvertPointer, UpdateCapsule).

  @return EFI_UNSUPPORTED  Always.
**/
STATIC
EFI_STATUS
EFIAPI
RtNotImplementedArg2 (
  UINTN Arg1,
  UINTN Arg2
  )
{
  return EFI_UNSUPPORTED;
}

STATIC
EFI_STATUS
EFIAPI
RtNotImplementedArg3 (
  UINTN Arg1,
  UINTN Arg2,
  UINTN Arg3
  )
{
  return EFI_UNSUPPORTED;
}

STATIC
EFI_STATUS
EFIAPI
RtNotImplementedArg4 (
  UINTN Arg1,
  UINTN Arg2,
  UINTN Arg3,
  UINTN Arg4
  )
{
  return EFI_UNSUPPORTED;
}

// ============================================================================
// Forward declarations for implemented services
// ============================================================================

EFI_STATUS
EFIAPI
CoreGetTime (
  OUT  EFI_TIME                    *Time,
  OUT  EFI_TIME_CAPABILITIES       *Capabilities OPTIONAL
  );

EFI_STATUS
EFIAPI
CoreSetTime (
  IN  EFI_TIME                     *Time
  );

EFI_STATUS
EFIAPI
CoreGetWakeupTime (
  OUT BOOLEAN                      *Enabled,
  OUT BOOLEAN                      *Pending,
  OUT EFI_TIME                     *Time
  );

EFI_STATUS
EFIAPI
CoreSetWakeupTime (
  IN  BOOLEAN                      Enable,
  IN  EFI_TIME                     *Time   OPTIONAL
  );

EFI_STATUS
EFIAPI
CoreSetVariable (
  IN  CHAR16                       *VariableName,
  IN  EFI_GUID                     *VendorGuid,
  IN  UINT32                       Attributes,
  IN  UINTN                        DataSize,
  IN  VOID                         *Data
  );

EFI_STATUS
EFIAPI
CoreGetVariable (
  IN     CHAR16                      *VariableName,
  IN     EFI_GUID                    *VendorGuid,
  OUT    UINT32                      *Attributes,    OPTIONAL
  IN OUT UINTN                       *DataSize,
  OUT    VOID                        *Data           OPTIONAL
  );

EFI_STATUS
EFIAPI
CoreGetNextVariableName (
  IN OUT UINTN                       *VariableNameSize,
  IN OUT CHAR16                      *VariableName,
  IN OUT EFI_GUID                    *VendorGuid
  );

EFI_STATUS
EFIAPI
CoreQueryVariableInfo (
  IN  UINT32                       Attributes,
  OUT UINT64                       *MaximumVariableStorageSize,
  OUT UINT64                       *RemainingVariableStorageSize,
  OUT UINT64                       *MaximumVariableSize
  );

// ============================================================================
// Locally implemented RT services
// ============================================================================

/**
  [AUDIT] GetNextHighMonotonicCount - Returns an incrementing 32-bit counter.
  UEFI Spec 8.5.3: Returns the next high 32 bits of the platform's monotonic
  counter. Our host implementation uses a simple static counter.

  @param[out] HighCount  Pointer to receive the counter value.

  @retval EFI_SUCCESS             Counter returned successfully.
  @retval EFI_INVALID_PARAMETER   HighCount is NULL.
**/
EFI_STATUS
EFIAPI
CoreGetNextHighMonotonicCount (
  OUT UINT32                       *HighCount
  )
{
  if (HighCount == NULL) {
    return EFI_INVALID_PARAMETER;
  }
  *HighCount = mHighMonotonicCount++;
  return EFI_SUCCESS;
}

/**
  [AUDIT] ResetSystem - No-op for host-based fuzzing.
  In a real UEFI system this would reset the platform. For fuzzing we want
  to continue execution so the fuzzer can complete the current iteration.
  This function intentionally does nothing and returns.

  @param[in] ResetType    The type of reset to perform (ignored).
  @param[in] ResetStatus  The status code for the reset (ignored).
  @param[in] DataSize     Size of ResetData (ignored).
  @param[in] ResetData    Optional reset data (ignored).
**/
VOID
EFIAPI
CoreResetSystem (
  IN EFI_RESET_TYPE           ResetType,
  IN EFI_STATUS               ResetStatus,
  IN UINTN                    DataSize,
  IN VOID                     *ResetData OPTIONAL
  )
{
  //
  // Intentional no-op for fuzzing. Do not exit or abort.
  //
  DEBUG ((DEBUG_INFO, "CoreResetSystem: type=%d status=%r (no-op)\n", ResetType, ResetStatus));
}

// ============================================================================
// Runtime Services Table
// ============================================================================

EFI_RUNTIME_SERVICES mEfiRuntimeServicesTableTemplate = {
  {
    EFI_RUNTIME_SERVICES_SIGNATURE,                               // Signature
    EFI_RUNTIME_SERVICES_REVISION,                                // Revision
    sizeof (EFI_RUNTIME_SERVICES),                                // HeaderSize
    0,                                                            // CRC32
    0                                                             // Reserved
  },
  (EFI_GET_TIME)                    CoreGetTime,                  // GetTime
  (EFI_SET_TIME)                    CoreSetTime,                  // SetTime
  (EFI_GET_WAKEUP_TIME)             CoreGetWakeupTime,            // GetWakeupTime
  (EFI_SET_WAKEUP_TIME)             CoreSetWakeupTime,            // SetWakeupTime
  (EFI_SET_VIRTUAL_ADDRESS_MAP)     RtNotImplementedArg4,         // SetVirtualAddressMap (stub)
  (EFI_CONVERT_POINTER)             RtNotImplementedArg2,         // ConvertPointer (stub)
  (EFI_GET_VARIABLE)                CoreGetVariable,              // GetVariable
  (EFI_GET_NEXT_VARIABLE_NAME)      CoreGetNextVariableName,      // GetNextVariableName
  (EFI_SET_VARIABLE)                CoreSetVariable,              // SetVariable
  (EFI_GET_NEXT_HIGH_MONO_COUNT)    CoreGetNextHighMonotonicCount,// GetNextHighMonotonicCount
  (EFI_RESET_SYSTEM)                CoreResetSystem,              // ResetSystem (no-op)
  (EFI_UPDATE_CAPSULE)              RtNotImplementedArg3,         // UpdateCapsule (stub)
  (EFI_QUERY_CAPSULE_CAPABILITIES)  RtNotImplementedArg4,         // QueryCapsuleCapabilities (stub)
  (EFI_QUERY_VARIABLE_INFO)         CoreQueryVariableInfo          // QueryVariableInfo
};
