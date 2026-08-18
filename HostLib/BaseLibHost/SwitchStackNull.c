/** @file SwitchStackNull.c
  Switch Stack stub for host-based fuzzing.

  AUDIT NOTES (HBFAplus host-fuzzing review):
  FIXED — replaced ASSERT(FALSE) with a no-op.  Stack switching is not
  applicable on the Linux host and crashing prevents edk2 code that
  references SwitchStack from being fuzzed.

  Copyright (c) 2006 - 2018, Intel Corporation. All rights reserved.<BR>
  SPDX-License-Identifier: BSD-2-Clause-Patent
**/

#include <Library/BaseLib.h>
#include <Library/DebugLib.h>

/**
  Transfers control to a function starting with a new stack.

  AUDIT: FIXED — no-op stub for host fuzzing.

  @param  EntryPoint  A pointer to function to call with the new stack.
  @param  Context1    A pointer to the context to pass into the EntryPoint function.
  @param  Context2    A pointer to the context to pass into the EntryPoint function.
  @param  NewStack    A pointer to the new stack to use for the EntryPoint function.
  @param  ...         Ignored on IA32/x64/EBC.
**/
VOID
EFIAPI
SwitchStack (
  IN      SWITCH_STACK_ENTRY_POINT  EntryPoint,
  IN      VOID                      *Context1,  OPTIONAL
  IN      VOID                      *Context2,  OPTIONAL
  IN      VOID                      *NewStack,
  ...
  )
{
  //
  // No-op: stack switching is not applicable on the Linux host.
  //
}
