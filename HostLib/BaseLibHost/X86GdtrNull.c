/** @file X86GdtrNull.c
  IA-32/x64 GDTR stubs for host-based fuzzing.

  AUDIT NOTES (HBFAplus host-fuzzing review):
  FIXED — replaced ASSERT(FALSE) with no-ops.  GDTR reads/writes are
  meaningless on a Linux host but some edk2 drivers call these during
  init.  Crashing on every call prevents those code paths from being
  fuzzed.  AsmReadGdtr now zeroes the output; AsmWriteGdtr is a no-op.

  Copyright (c) 2006 - 2008, Intel Corporation. All rights reserved.<BR>
  SPDX-License-Identifier: BSD-2-Clause-Patent
**/

#include <Library/BaseLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/DebugLib.h>

/**
  Reads the current Global Descriptor Table Register(GDTR) descriptor.

  AUDIT: FIXED — no longer asserts.  Zeroes the output structure.

  @param  Gdtr  The pointer to a GDTR descriptor.
**/
VOID
EFIAPI
AsmReadGdtr (
  OUT     IA32_DESCRIPTOR           *Gdtr
  )
{
  if (Gdtr != NULL) {
    ZeroMem (Gdtr, sizeof (*Gdtr));
  }
}

/**
  Writes the current Global Descriptor Table Register (GDTR) descriptor.

  AUDIT: FIXED — no-op stub.  Writing GDTR is meaningless on host.

  @param  Gdtr  The pointer to a GDTR descriptor.
**/
VOID
EFIAPI
AsmWriteGdtr (
  IN      CONST IA32_DESCRIPTOR     *Gdtr
  )
{
  //
  // No-op: GDTR is not applicable on the Linux host.
  //
}
