/** @file
  Host-based RegisterFilterLib — intercepts MMIO, Port I/O, and MSR reads,
  returning values from the shared FuzzContextLib byte pool.

  All writes are ignored (no-op).  Supports AFL++ persistent mode.

  This library overrides edk2's RegisterFilterLibNull globally in the
  HBFAplus DSC.  It consumes fuzzer bytes from the single
  MOCK_FUZZ_CONTEXT pool owned by FuzzContextLib.  It does NOT own the
  pool — ToolChainHarnessLib is the sole authority for
  MockFuzzContextInit / MockFuzzContextReset.

  Enable debug logging by setting FUZZ_IO_DEBUG=1 environment variable.

  RegisterFilterLib API (12 functions):
    FilterBeforeIoRead      — Port I/O read: consumes Width bytes, returns FALSE
    FilterAfterIoRead       — No-op
    FilterBeforeIoWrite     — No-op, returns FALSE (skip write)
    FilterAfterIoWrite      — No-op
    FilterBeforeMmIoRead    — MMIO read: consumes Width bytes, returns FALSE
    FilterAfterMmIoRead     — No-op
    FilterBeforeMmIoWrite   — No-op, returns FALSE (skip write)
    FilterAfterMmIoWrite    — No-op
    FilterBeforeMsrRead     — MSR read: consumes 8 bytes, returns FALSE
    FilterAfterMsrRead      — No-op
    FilterBeforeMsrWrite    — No-op, returns FALSE (skip write)
    FilterAfterMsrWrite     — No-op

  Internal helpers (2 functions):
    InitDebugLogging        — One-time check for FUZZ_IO_DEBUG env var
    GetWidthByteCount       — FILTER_IO_WIDTH -> byte count
    ReadFuzzBytes           — Consume from context or zero-fill

  Design notes:
  - All Before*Read functions return FALSE to skip real HW access
  - All Before*Write functions return FALSE to skip real HW writes
  - All After* functions are no-ops (tracing hooks, unused on host)
  - Exhausted buffer -> zero-fill (simulates powered-down device)
  - NULL buffer handled gracefully (zero-fill)
  - No ASSERT(FALSE) anywhere — safe for fuzzing
  - No memory allocation — all state is STATIC globals

  vs. edk2 RegisterFilterLibNull:
  - Null lib returns TRUE (execute real HW access) for all Before*
  - Host lib returns FALSE (skip) for all Before* — correct for fuzzing
  - Otherwise identical API surface

  Copyright (c) 2026, Intel Corporation. All rights reserved.<BR>
  SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <Uefi.h>
#include <Library/BaseLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/RegisterFilterLib.h>
#include <Library/FuzzContextLib.h>

//
// ============================================================================
// Internal State
// ============================================================================
//

STATIC BOOLEAN            gDebugEnabled  = FALSE;
STATIC BOOLEAN            gInitialized   = FALSE;

/**
  Get the byte count for a given filter width.

  @param[in]  Width  The filter I/O width.

  @return The number of bytes for this width.
**/
STATIC
UINTN
GetWidthByteCount (
  IN FILTER_IO_WIDTH  Width
  )
{
  switch (Width) {
    case FilterWidth8:
      return 1;
    case FilterWidth16:
      return 2;
    case FilterWidth32:
      return 4;
    case FilterWidth64:
      return 8;
    default:
      return 1;
  }
}

/**
  One-time check for FUZZ_IO_DEBUG environment variable.  Called
  lazily on the first ReadFuzzBytes invocation.
**/
STATIC
VOID
InitDebugLogging (
  VOID
  )
{
  CHAR8  *DebugEnv;

  if (gInitialized) {
    return;
  }

  gInitialized = TRUE;

  DebugEnv = getenv ("FUZZ_IO_DEBUG");
  if (DebugEnv != NULL && (DebugEnv[0] == '1' || DebugEnv[0] == 'y' || DebugEnv[0] == 'Y')) {
    gDebugEnabled = TRUE;
    fprintf (stderr, "[RegisterFilterLibHost] Debug logging enabled\n");
  }
}

/**
  Read bytes from the shared fuzz context.  If the context is exhausted or
  not yet initialised, the destination buffer is zero-filled — identical to
  the behaviour a real register read would show on a powered-down device.

  @param[out] Buffer     Destination buffer to store the read bytes.
  @param[in]  ByteCount  Number of bytes to read.
**/
STATIC
VOID
ReadFuzzBytes (
  OUT VOID   *Buffer,
  IN  UINTN  ByteCount
  )
{
  UINT8  *Data;

  if (Buffer == NULL || ByteCount == 0) {
    return;
  }

  if (!gInitialized) {
    InitDebugLogging ();
  }

  Data = MockFuzzContextConsume (MockFuzzContextGetPool (), ByteCount);
  if (Data != NULL) {
    CopyMem (Buffer, Data, ByteCount);
  } else {
    ZeroMem (Buffer, ByteCount);
  }
}

//
// ============================================================================
// RegisterFilterLib Interface Implementation - I/O Port Operations
// ============================================================================
//

/**
  Filter IO read operation before read IO port.
  Consumes bytes from fuzz context and returns FALSE to skip actual read.

  @param[in]       Width    Signifies the width of the I/O operation.
  @param[in]       Address  The base address of the I/O operation.
  @param[in,out]   Buffer   The destination buffer to store the results.

  @retval FALSE    Skip the IO read (value provided from fuzz context).
**/
BOOLEAN
EFIAPI
FilterBeforeIoRead (
  IN FILTER_IO_WIDTH  Width,
  IN UINTN            Address,
  IN OUT VOID         *Buffer
  )
{
  UINTN   ByteCount;
  UINT64  Value = 0;

  ByteCount = GetWidthByteCount (Width);
  ReadFuzzBytes (&Value, ByteCount);
  CopyMem (Buffer, &Value, ByteCount);

  if (gDebugEnabled) {
    fprintf (stderr, "PORT READ  port=0x%lx width=%lu value=0x%llx\n",
             (unsigned long)Address, (unsigned long)(ByteCount * 8), (unsigned long long)Value);
  }

  return FALSE;  // Skip actual I/O read
}

/**
  Trace IO read operation after read IO port.
  No-op for host implementation.

  @param[in]       Width    Signifies the width of the I/O operation.
  @param[in]       Address  The base address of the I/O operation.
  @param[in]       Buffer   The destination buffer to store the results.
**/
VOID
EFIAPI
FilterAfterIoRead (
  IN FILTER_IO_WIDTH  Width,
  IN UINTN            Address,
  IN VOID             *Buffer
  )
{
  // No-op
}

/**
  Filter IO Write operation before write IO port.
  Returns FALSE to skip actual write (ignore all writes).

  @param[in]       Width    Signifies the width of the I/O operation.
  @param[in]       Address  The base address of the I/O operation.
  @param[in]       Buffer   The source buffer from which to write data.

  @retval FALSE    Skip the IO write.
**/
BOOLEAN
EFIAPI
FilterBeforeIoWrite (
  IN FILTER_IO_WIDTH  Width,
  IN UINTN            Address,
  IN VOID             *Buffer
  )
{
  if (gDebugEnabled) {
    UINTN   ByteCount = GetWidthByteCount (Width);
    UINT64  Value = 0;
    CopyMem (&Value, Buffer, ByteCount);
    fprintf (stderr, "PORT WRITE port=0x%lx width=%lu value=0x%llx (ignored)\n",
             (unsigned long)Address, (unsigned long)(ByteCount * 8), (unsigned long long)Value);
  }

  return FALSE;  // Skip actual I/O write
}

/**
  Trace IO Write operation after write IO port.
  No-op for host implementation.

  @param[in]       Width    Signifies the width of the I/O operation.
  @param[in]       Address  The base address of the I/O operation.
  @param[in]       Buffer   The source buffer from which to write data.
**/
VOID
EFIAPI
FilterAfterIoWrite (
  IN FILTER_IO_WIDTH  Width,
  IN UINTN            Address,
  IN VOID             *Buffer
  )
{
  // No-op
}

//
// ============================================================================
// RegisterFilterLib Interface Implementation - MMIO Operations
// ============================================================================
//

/**
  Filter memory IO before Read operation.
  Consumes bytes from fuzz context and returns FALSE to skip actual read.

  @param[in]       Width    Signifies the width of the memory I/O operation.
  @param[in]       Address  The base address of the memory I/O operation.
  @param[in,out]   Buffer   The destination buffer to store the results.

  @retval FALSE    Skip the MMIO read (value provided from fuzz context).
**/
BOOLEAN
EFIAPI
FilterBeforeMmIoRead (
  IN FILTER_IO_WIDTH  Width,
  IN UINTN            Address,
  IN OUT VOID         *Buffer
  )
{
  UINTN   ByteCount;
  UINT64  Value = 0;

  ByteCount = GetWidthByteCount (Width);
  ReadFuzzBytes (&Value, ByteCount);
  CopyMem (Buffer, &Value, ByteCount);

  if (gDebugEnabled) {
    fprintf (stderr, "MMIO READ  addr=0x%lx width=%lu value=0x%llx\n",
             (unsigned long)Address, (unsigned long)(ByteCount * 8), (unsigned long long)Value);
  }

  return FALSE;  // Skip actual MMIO read
}

/**
  Tracer memory IO after read operation.
  No-op for host implementation.

  @param[in]       Width    Signifies the width of the memory I/O operation.
  @param[in]       Address  The base address of the memory I/O operation.
  @param[in]       Buffer   The destination buffer to store the results.
**/
VOID
EFIAPI
FilterAfterMmIoRead (
  IN FILTER_IO_WIDTH  Width,
  IN UINTN            Address,
  IN VOID             *Buffer
  )
{
  // No-op
}

/**
  Filter memory IO before write operation.
  Returns FALSE to skip actual write (ignore all writes).

  @param[in]       Width    Signifies the width of the memory I/O operation.
  @param[in]       Address  The base address of the memory I/O operation.
  @param[in]       Buffer   The source buffer from which to write data.

  @retval FALSE    Skip the MMIO write.
**/
BOOLEAN
EFIAPI
FilterBeforeMmIoWrite (
  IN FILTER_IO_WIDTH  Width,
  IN UINTN            Address,
  IN VOID             *Buffer
  )
{
  if (gDebugEnabled) {
    UINTN   ByteCount = GetWidthByteCount (Width);
    UINT64  Value = 0;
    CopyMem (&Value, Buffer, ByteCount);
    fprintf (stderr, "MMIO WRITE addr=0x%lx width=%lu value=0x%llx (ignored)\n",
             (unsigned long)Address, (unsigned long)(ByteCount * 8), (unsigned long long)Value);
  }

  return FALSE;  // Skip actual MMIO write
}

/**
  Tracer memory IO after write operation.
  No-op for host implementation.

  @param[in]       Width    Signifies the width of the memory I/O operation.
  @param[in]       Address  The base address of the memory I/O operation.
  @param[in]       Buffer   The source buffer from which to write data.
**/
VOID
EFIAPI
FilterAfterMmIoWrite (
  IN FILTER_IO_WIDTH  Width,
  IN UINTN            Address,
  IN VOID             *Buffer
  )
{
  // No-op
}

//
// ============================================================================
// RegisterFilterLib Interface Implementation - MSR Operations
// ============================================================================
//

/**
  Filter MSR before read operation.
  Consumes 8 bytes from fuzz context and returns FALSE to skip actual read.

  @param[in]       Index    The Register index of the MSR.
  @param[in,out]   Value    Point to the data will be read from the MSR.

  @retval FALSE    Skip the MSR read (value provided from fuzz context).
**/
BOOLEAN
EFIAPI
FilterBeforeMsrRead (
  IN UINT32      Index,
  IN OUT UINT64  *Value
  )
{
  UINT64  FuzzValue = 0;

  ReadFuzzBytes (&FuzzValue, sizeof (UINT64));
  *Value = FuzzValue;

  if (gDebugEnabled) {
    fprintf (stderr, "MSR  READ  index=0x%x value=0x%llx\n",
             (unsigned int)Index, (unsigned long long)FuzzValue);
  }

  return FALSE;  // Skip actual MSR read
}

/**
  Trace MSR after read operation.
  No-op for host implementation.

  @param[in]  Index   The Register index of the MSR.
  @param[in]  Value   Point to the data has been read from the MSR.
**/
VOID
EFIAPI
FilterAfterMsrRead (
  IN UINT32  Index,
  IN UINT64  *Value
  )
{
  // No-op
}

/**
  Filter MSR before write operation.
  Returns FALSE to skip actual write (ignore all writes).

  @param[in]  Index   The Register index of the MSR.
  @param[in]  Value   Point to the data want to be written to the MSR.

  @retval FALSE    Skip the MSR write.
**/
BOOLEAN
EFIAPI
FilterBeforeMsrWrite (
  IN UINT32  Index,
  IN UINT64  *Value
  )
{
  if (gDebugEnabled) {
    fprintf (stderr, "MSR  WRITE index=0x%x value=0x%llx (ignored)\n",
             (unsigned int)Index, (unsigned long long)*Value);
  }

  return FALSE;  // Skip actual MSR write
}

/**
  Trace MSR after write operation.
  No-op for host implementation.

  @param[in]  Index   The Register index of the MSR.
  @param[in]  Value   Point to the data has been written to the MSR.
**/
VOID
EFIAPI
FilterAfterMsrWrite (
  IN UINT32  Index,
  IN UINT64  *Value
  )
{
  // No-op
}
