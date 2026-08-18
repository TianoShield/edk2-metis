/** @file CpuBreakpointGcc.c
  CpuBreakpoint function — host-fuzzing override.

  AUDIT NOTES (HBFAplus host-fuzzing review):
  FIXED — The original GCC implementation issues "int $3" which raises
  SIGTRAP and kills the process under AFL++.  In the host fuzzer a
  breakpoint is a no-op: we simply return so execution continues.

  Copyright (c) 2006 - 2008, Intel Corporation. All rights reserved.<BR>
  SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include <Base.h>
#include <Library/BaseLib.h>

/**
  Generates a breakpoint on the CPU.

  AUDIT: FIXED — On real hardware "int $3" traps to a debugger.
  Under host fuzzing this raises SIGTRAP which crashes the process
  and causes false-positive crashes in AFL++.  Changed to a no-op
  so execution continues normally.
**/
VOID
EFIAPI
CpuBreakpoint (
  VOID
  )
{
  //
  // No-op under host fuzzing — see AUDIT note above.
  //
  return;
}
