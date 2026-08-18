/** @file BaseMemoryLibHost.c
  Host-based implementation of BaseMemoryLib for UEFI rehosting and fuzzing.

  All memory operations delegate to libc (memset, memmove, memcmp, memchr)
  which is correct for a Linux host environment.  The host has no cache
  coherency domain or alignment restrictions that differ from normal C
  semantics, so direct libc usage faithfully mimics UEFI behaviour while
  remaining safe for fuzzing.

  AUDIT NOTES (HBFAplus host-fuzzing review):
  - SetMem / ZeroMem / CopyMem / CompareMem: Thin wrappers over libc.
    Correct and fuzz-safe.
  - SetMem16/32/64: 'Length' parameter is in BYTES (matching the edk2 public
    API contract in MdePkg/Include/Library/BaseMemoryLib.h and the edk2
    SetMem*Wrapper.c implementations which divide by sizeof(Value) before
    filling).  We do the same division here.
  - CompareGuid / CopyGuid / IsZeroGuid: Use memcmp/memmove.  Correct.
  - ScanMem8: Wraps memchr.  Correct.
  - InternalMemIsZeroBuffer / IsZeroBuffer: FIXED - replaced CpuBreakpoint()
    crash-on-NULL with ASSERT() macro that is debug-only and non-fatal in
    release builds.  Fuzzers can now exercise NULL/zero-length paths without
    crashing.

  Copyright (c) 2018, Intel Corporation. All rights reserved.<BR>
  SPDX-License-Identifier: BSD-2-Clause-Patent
**/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include <Uefi.h>
#include <Library/DebugLib.h>
#define MAX_ADDRESS   0xFFFFFFFFFFFFFFFFULL
VOID *
EFIAPI
SetMem (
  OUT VOID  *Buffer,
  IN UINTN  Length,
  IN UINT8  Value
  )
{
  memset (Buffer, Value, Length);
  return Buffer;
}

/**
  Fills a target buffer with a 16-bit value, and returns the target buffer.

  UEFI/edk2 contract (SetMem16Wrapper.c):
    - Length is in BYTES, not elements.
    - Length must be aligned to sizeof(UINT16).
    - edk2 divides Length by sizeof(UINT16) before the fill loop.
    - Returns Buffer unchanged if Length == 0.

  Host deviation: None — we match edk2 semantics exactly.

  @param[out]  Buffer  Pointer to the target buffer.
  @param[in]   Length  Number of BYTES to fill (must be multiple of 2).
  @param[in]   Value   16-bit value to fill with.

  @return Buffer.
**/
VOID *
EFIAPI
SetMem16 (
  OUT VOID   *Buffer,
  IN UINTN   Length,
  IN UINT16  Value
  )
{
  UINTN  Count;

  if (Length == 0) {
    return Buffer;
  }

  //
  // Convert byte count to element count, matching edk2 SetMem16Wrapper.c:
  //   return InternalMemSetMem16 (Buffer, Length / sizeof (Value), Value);
  //
  Count = Length / sizeof (UINT16);
  for (; Count != 0; Count--) {
    ((UINT16*)Buffer)[Count - 1] = Value;
  }
  return Buffer;
}

/**
  Fills a target buffer with a 32-bit value, and returns the target buffer.

  UEFI/edk2 contract (SetMem32Wrapper.c):
    - Length is in BYTES, not elements.
    - Length must be aligned to sizeof(UINT32).
    - edk2 divides Length by sizeof(UINT32) before the fill loop.
    - Returns Buffer unchanged if Length == 0.

  Host deviation: None — we match edk2 semantics exactly.

  @param[out]  Buffer  Pointer to the target buffer.
  @param[in]   Length  Number of BYTES to fill (must be multiple of 4).
  @param[in]   Value   32-bit value to fill with.

  @return Buffer.
**/
VOID *
EFIAPI
SetMem32 (
  OUT VOID   *Buffer,
  IN UINTN   Length,
  IN UINT32  Value
  )
{
  UINTN  Count;

  if (Length == 0) {
    return Buffer;
  }

  //
  // Convert byte count to element count, matching edk2 SetMem32Wrapper.c:
  //   return InternalMemSetMem32 (Buffer, Length / sizeof (Value), Value);
  //
  Count = Length / sizeof (UINT32);
  for (; Count != 0; Count--) {
    ((UINT32*)Buffer)[Count - 1] = Value;
  }
  return Buffer;
}

/**
  Fills a target buffer with a 64-bit value, and returns the target buffer.

  UEFI/edk2 contract (SetMem64Wrapper.c):
    - Length is in BYTES, not elements.
    - Length must be aligned to sizeof(UINT64).
    - edk2 divides Length by sizeof(UINT64) before the fill loop.
    - Returns Buffer unchanged if Length == 0.

  Host deviation: None — we match edk2 semantics exactly.

  @param[out]  Buffer  Pointer to the target buffer.
  @param[in]   Length  Number of BYTES to fill (must be multiple of 8).
  @param[in]   Value   64-bit value to fill with.

  @return Buffer.
**/
VOID *
EFIAPI
SetMem64 (
  OUT VOID   *Buffer,
  IN UINTN   Length,
  IN UINT64  Value
  )
{
  UINTN  Count;

  if (Length == 0) {
    return Buffer;
  }

  //
  // Convert byte count to element count, matching edk2 SetMem64Wrapper.c:
  //   return InternalMemSetMem64 (Buffer, Length / sizeof (Value), Value);
  //
  Count = Length / sizeof (UINT64);
  for (; Count != 0; Count--) {
    ((UINT64*)Buffer)[Count - 1] = Value;
  }
  return Buffer;
}

VOID *
EFIAPI
SetMemN (
  OUT VOID  *Buffer,
  IN UINTN  Length,
  IN UINTN  Value
  )
{
  if (sizeof (UINTN) == sizeof (UINT64)) {
    return SetMem64 (Buffer, Length, (UINT64)Value);
  } else {
    return SetMem32 (Buffer, Length, (UINT32)Value);
  }
}

VOID *
EFIAPI
ZeroMem (
  OUT VOID  *Buffer,
  IN UINTN  Length
  )
{
  memset (Buffer, 0, Length);
  return Buffer;
}

VOID *
EFIAPI
CopyMem (
  OUT VOID       *DestinationBuffer,
  IN CONST VOID  *SourceBuffer,
  IN UINTN       Length
  )
{
  memmove (DestinationBuffer, SourceBuffer, Length);
  return DestinationBuffer;
}

INTN
EFIAPI
CompareMem (
  IN CONST VOID  *DestinationBuffer,
  IN CONST VOID  *SourceBuffer,
  IN UINTN       Length
  )
{
  return memcmp (DestinationBuffer, SourceBuffer, Length);
}

BOOLEAN
EFIAPI
CompareGuid (
  IN CONST GUID  *Guid1,
  IN CONST GUID  *Guid2
  )
{
  return ((BOOLEAN)(memcmp (Guid1, Guid2, sizeof (GUID)) == 0));
}

GUID *
EFIAPI
CopyGuid (
  OUT GUID       *DestinationGuid,
  IN CONST GUID  *SourceGuid
  )
{
  memmove (DestinationGuid, SourceGuid, sizeof(GUID));
  return DestinationGuid;
}

UINT8 mZeroGuid[sizeof(GUID)] = {0};

BOOLEAN
EFIAPI
IsZeroGuid (
  IN CONST GUID  *Guid
  )
{
  return ((BOOLEAN)(memcmp (Guid, mZeroGuid, sizeof (GUID)) == 0));
}

VOID *
EFIAPI
ScanMem8 (
  IN CONST VOID  *Buffer,
  IN UINTN       Length,
  IN UINT8       Value
  )
{
  return memchr (Buffer, Value, Length);
}

/**
  Checks whether the contents of a buffer are all zeros.

  AUDIT: FIXED - replaced CpuBreakpoint() with ASSERT() macro so NULL/zero-length
  inputs do not crash the fuzzer.  Returns FALSE for invalid inputs.

  @param  Buffer  The pointer to the buffer to be checked.
  @param  Length  The size of the buffer (in bytes) to be checked.

  @retval TRUE    Contents of the buffer are all zeros.
  @retval FALSE   Contents of the buffer are not all zeros, or invalid input.

**/
BOOLEAN
EFIAPI
InternalMemIsZeroBuffer (
  IN CONST VOID  *Buffer,
  IN UINTN       Length
  )
{
  CONST UINT8 *BufferData;
  UINTN       Index;

  ASSERT (Buffer != NULL);
  ASSERT (Length > 0);
  if (Buffer == NULL || Length == 0) {
    return FALSE;
  }
  BufferData = Buffer;
  for (Index = 0; Index < Length; Index++) {
    if (BufferData[Index] != 0) {
      return FALSE;
    }
  }
  return TRUE;
}

/**
  Checks if the contents of a buffer are all zeros.

  This function checks whether the contents of a buffer are all zeros. If the
  contents are all zeros, return TRUE. Otherwise, return FALSE.

  AUDIT: FIXED - replaced printf+CpuBreakpoint() with ASSERT() macro.
  Returns FALSE for invalid inputs instead of crashing.

  If Length > 0 and Buffer is NULL, then ASSERT().
  If Length is greater than (MAX_ADDRESS - Buffer + 1), then ASSERT().

  @param  Buffer      The pointer to the buffer to be checked.
  @param  Length      The size of the buffer (in bytes) to be checked.

  @retval TRUE        Contents of the buffer are all zeros.
  @retval FALSE       Contents of the buffer are not all zeros, or invalid input.

**/
BOOLEAN
EFIAPI
IsZeroBuffer (
  IN CONST VOID  *Buffer,
  IN UINTN       Length
  )
{
  ASSERT (Buffer != NULL || Length == 0);
  if (Buffer == NULL || Length == 0) {
    return FALSE;
  }
  return InternalMemIsZeroBuffer (Buffer, Length);
}