/** @file CpuDeadLoop.c
  Base Library CPU Functions for all architectures.

  AUDIT NOTES (HBFAplus host-fuzzing review):
  FIXED — CpuDeadLoop() was an actual infinite loop which hangs the fuzzer.
  Changed to a no-op (immediate return).  In a real UEFI environment this is
  typically called after a fatal error; in the host fuzzer we want to continue
  execution so the harness can report the issue and move on.

  Copyright (c) 2006 - 2008, Intel Corporation. All rights reserved.<BR>
  SPDX-License-Identifier: BSD-2-Clause-Patent
**/

#include <Base.h>
#include <Library/BaseLib.h>
#include <stdio.h>
#include <stdlib.h>

/**
  Executes an infinite loop.

  AUDIT: FIXED — On real UEFI hardware CpuDeadLoop() is called after an
  unrecoverable fatal error and the CPU halts permanently.  In the host
  fuzzing environment we call exit(1) to cleanly terminate the process.
  This lets the fuzzer detect that a fatal error path was reached (non-zero
  exit code) without hanging on an infinite loop or silently continuing
  into undefined post-fatal state.

**/
VOID
EFIAPI
CpuDeadLoop (
  VOID
  )
{
  fprintf (stderr, "[CpuDeadLoop] Fatal error path reached — terminating.\n");
  exit (1);
}
