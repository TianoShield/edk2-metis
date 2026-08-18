/** @file
  Host-safe deterministic stubs for InternalX86RdRand16/32/64.

  Replace the real RDRAND NASM implementations with simple C stubs for
  host-based fuzzing.  The assembly originals use MS ABI register
  conventions (rcx = first arg) which conflict with the SystemV ABI
  used by GCC5 host builds.

  Copyright (c) 2025, HBFAplus Contributors. All rights reserved.
  SPDX-License-Identifier: BSD-2-Clause-Patent
**/

#include <Base.h>

/**
  Deterministic stub for InternalX86RdRand16.
**/
BOOLEAN
EFIAPI
InternalX86RdRand16 (
  OUT UINT16  *Rand
  )
{
  *Rand = 0xBEEF;
  return TRUE;
}

/**
  Deterministic stub for InternalX86RdRand32.
**/
BOOLEAN
EFIAPI
InternalX86RdRand32 (
  OUT UINT32  *Rand
  )
{
  *Rand = 0xDEADBEEF;
  return TRUE;
}

/**
  Deterministic stub for InternalX86RdRand64.
**/
BOOLEAN
EFIAPI
InternalX86RdRand64 (
  OUT UINT64  *Rand
  )
{
  *Rand = 0xDEADBEEFCAFEBABEULL;
  return TRUE;
}
