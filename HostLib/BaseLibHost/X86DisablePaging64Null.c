/** @file X86DisablePaging64Null.c
  IA-32/x64 AsmDisablePaging64() stub for host-based fuzzing.

  AUDIT NOTES (HBFAplus host-fuzzing review):
  FIXED — replaced ASSERT(FALSE) with a no-op.  Paging mode transitions
  are inapplicable on the Linux host.

  Copyright (c) 2006 - 2008, Intel Corporation. All rights reserved.<BR>
  SPDX-License-Identifier: BSD-2-Clause-Patent
**/

#include <Library/BaseLib.h>
#include <Library/DebugLib.h>

/**
  Disables the 64-bit paging mode on the CPU.

  AUDIT: FIXED — no-op stub for host fuzzing.

  @param  Cs          Code segment selector.
  @param  EntryPoint  Function to call after paging is disabled.
  @param  Context1    First parameter for EntryPoint.
  @param  Context2    Second parameter for EntryPoint.
  @param  NewStack    Stack to use for EntryPoint.
**/
VOID
EFIAPI
AsmDisablePaging64 (
  IN      UINT16                    Cs,
  IN      UINT32                    EntryPoint,
  IN      UINT32                    Context1,  OPTIONAL
  IN      UINT32                    Context2,  OPTIONAL
  IN      UINT32                    NewStack
  )
{
  //
  // No-op: paging mode transitions are not applicable on the Linux host.
  //
}
