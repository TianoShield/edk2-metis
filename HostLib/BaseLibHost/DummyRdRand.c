/** @file DummyRdRand.c
  Host-based stub for InternalX86RdRand16/32/64.

  AUDIT NOTES (HBFAplus host-fuzzing review):
  FIXED — original stubs returned TRUE (success) without writing any value
  to the *Rand output pointer, causing callers to consume uninitialised
  memory.  Now writes a deterministic non-zero value (0xDEAD… pattern)
  and returns TRUE.  Deterministic values keep fuzzing reproducible.

  Copyright (c) 2016, Intel Corporation. All rights reserved.<BR>
  SPDX-License-Identifier: BSD-2-Clause-Patent
**/

#include <Base.h>
#include <Library/BaseLib.h>
#include <Library/DebugLib.h>

/**
  Generates a 16-bit random number through RDRAND instruction.

  AUDIT: FIXED - writes a deterministic value so callers always read valid data.

  @param[out]  Rand     Buffer pointer to store the random result.
  @retval TRUE          RDRAND call was successful.
**/
BOOLEAN
EFIAPI
InternalX86RdRand16 (
  OUT     UINT16                    *Rand
  )
{
  if (Rand != NULL) {
    *Rand = 0xDEAD;
  }
  return TRUE;
}

/**
  Generates a 32-bit random number through RDRAND instruction.

  AUDIT: FIXED - writes a deterministic value so callers always read valid data.

  @param[out]  Rand     Buffer pointer to store the random result.
  @retval TRUE          RDRAND call was successful.
**/
BOOLEAN
EFIAPI
InternalX86RdRand32 (
  OUT     UINT32                    *Rand
  )
{
  if (Rand != NULL) {
    *Rand = 0xDEADBEEF;
  }
  return TRUE;
}

/**
  Generates a 64-bit random number through RDRAND instruction.

  AUDIT: FIXED - writes a deterministic value so callers always read valid data.

  @param[out]  Rand     Buffer pointer to store the random result.
  @retval TRUE          RDRAND call was successful.
**/
BOOLEAN
EFIAPI
InternalX86RdRand64  (
  OUT     UINT64                    *Rand
  )
{
  if (Rand != NULL) {
    *Rand = 0xDEADBEEFCAFEBABEULL;
  }
  return TRUE;
}
