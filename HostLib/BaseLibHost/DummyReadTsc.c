/** @file DummyReadTsc.c
  Host-based stub for AsmReadTsc.

  AUDIT NOTES (HBFAplus host-fuzzing review):
  Returns 0.  This is safe — callers using TSC for timing will get
  deterministic results, which is desirable for reproducible fuzzing.

  Copyright (c) 2016, Intel Corporation. All rights reserved.<BR>
  SPDX-License-Identifier: BSD-2-Clause-Patent
**/

#include <Base.h>
#include <Library/BaseLib.h>
#include <Library/DebugLib.h>

/**
  Reads the current value of Time Stamp Counter (TSC).

  AUDIT: Returns 0 — deterministic for fuzzing.

  @return The current value of TSC.
**/
UINT64
EFIAPI
AsmReadTsc (
  VOID
  )
{
  return 0;
}
