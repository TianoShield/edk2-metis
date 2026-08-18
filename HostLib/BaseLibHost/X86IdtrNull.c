/** @file X86IdtrNull.c
  IA-32/x64 IDTR stubs for host-based fuzzing.

  AUDIT NOTES (HBFAplus host-fuzzing review):
  FIXED — replaced ASSERT(FALSE) with no-ops.  Same rationale as GDTR stubs.

  Copyright (c) 2006 - 2008, Intel Corporation. All rights reserved.<BR>
  SPDX-License-Identifier: BSD-2-Clause-Patent
**/

#include <Library/BaseLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/DebugLib.h>

/**
  Reads the current Interrupt Descriptor Table Register(IDTR) descriptor.

  AUDIT: FIXED — zeroes the output instead of asserting.

  @param  Idtr  The pointer to a IDTR descriptor.
**/
VOID
EFIAPI
AsmReadIdtr (
  OUT     IA32_DESCRIPTOR           *Idtr
  )
{
  if (Idtr != NULL) {
    ZeroMem (Idtr, sizeof (*Idtr));
  }
}

/**
  Writes the current Interrupt Descriptor Table Register(IDTR) descriptor.

  AUDIT: FIXED — no-op stub.

  @param  Idtr  The pointer to a IDTR descriptor.
**/
VOID
EFIAPI
AsmWriteIdtr (
  IN      CONST IA32_DESCRIPTOR     *Idtr
  )
{
  //
  // No-op: IDTR is not applicable on the Linux host.
  //
}
