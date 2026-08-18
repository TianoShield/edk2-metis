/** @file MockgEfiRngProtocolGuid.c
    HBFAplus Mock Random Number Generator Protocol Library Implementation.

    Provides a mock EFI_RNG_PROTOCOL for fuzzing drivers that consume
    random data. Returns deterministic, fuzzer-controlled values.

    Copyright (c) 2025, HBFAplus Contributors. All rights reserved.
    SPDX-License-Identifier: BSD-2-Clause-Patent
**/

//=============================================================================
// UEFI Spec Audit — §37.5 (EFI Random Number Generator Protocol)
//
// Real UEFI: GetInfo/GetRNG to obtain random data from hardware RNG.
// Our mock:  Returns deterministic fuzzer-controlled values.
// Deviations: No real entropy — output is fuzz-driven.
//=============================================================================

#include <Uefi.h>
#include <Library/BaseMemoryLib.h>
#include <Library/DebugLib.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Protocol/Rng.h>
#include <Library/FuzzContextLib.h>

//
// Shared handle where all mock protocols are installed
//
extern EFI_HANDLE gFuzzHandle;

//=============================================================================
// Global State
//=============================================================================

//
// Mock RNG protocol instance
//
STATIC EFI_RNG_PROTOCOL  mMockRngProtocol;

//
// Fuzz context - resolved dynamically via ResolveContext()
//

//
// Deterministic PRNG state (used when no fuzz context)
// Uses m-prefix: file-scope static per EDK II coding convention.
//
STATIC UINT64  mPrngState = 0x12345678ABCDEF01ULL;

//
// Standard RNG algorithm GUID (SP800-90 Hash_DRBG using SHA-256)
//
STATIC EFI_RNG_ALGORITHM  mSupportedAlgorithms[] = {
  EFI_RNG_ALGORITHM_SP800_90_HASH_256_GUID
};

//=============================================================================
// Simple PRNG (xorshift64* for deterministic mode)
//=============================================================================

/**
  Advance the xorshift64* PRNG by one step.

  @return  Next pseudo-random 64-bit value.
**/
STATIC
UINT64
PrngNext (
  VOID
  )
{
  UINT64  x = mPrngState;
  
  x ^= x >> 12;
  x ^= x << 25;
  x ^= x >> 27;
  mPrngState = x;
  
  return x * 0x2545F4914F6CDD1DULL;
}

//=============================================================================
// Mock Protocol Functions
//=============================================================================

STATIC
EFI_STATUS
EFIAPI
MockRngGetInfo (
  IN EFI_RNG_PROTOCOL      *This,
  IN OUT UINTN             *RNGAlgorithmListSize,
  OUT EFI_RNG_ALGORITHM    *RNGAlgorithmList      OPTIONAL
  )
{
  UINTN  RequiredSize;

  DEBUG ((DEBUG_INFO, "MockRng: GetInfo\n"));

  if (This == NULL || RNGAlgorithmListSize == NULL) {
    return EFI_INVALID_PARAMETER;
  }

  RequiredSize = sizeof (mSupportedAlgorithms);

  if (*RNGAlgorithmListSize < RequiredSize) {
    *RNGAlgorithmListSize = RequiredSize;
    return EFI_BUFFER_TOO_SMALL;
  }

  if (RNGAlgorithmList != NULL) {
    CopyMem (RNGAlgorithmList, mSupportedAlgorithms, RequiredSize);
  }

  *RNGAlgorithmListSize = RequiredSize;
  return EFI_SUCCESS;
}

/**
  Resolve the effective fuzz context for this protocol.

  Checks the protocol context registry for a harness-provided override;
  falls back to the cached global pool pointer.

  @return  Active fuzz context, or NULL if none available.
**/
STATIC
MOCK_FUZZ_CONTEXT *
ResolveContext (
  VOID
  )
{
  MOCK_FUZZ_CONTEXT  *Override;

  Override = MockFuzzContextGetProtocolContext (&gEfiRngProtocolGuid);
  return (Override != NULL) ? Override : MockFuzzContextGetPool ();
}

STATIC
EFI_STATUS
EFIAPI
MockRngGetRNG (
  IN EFI_RNG_PROTOCOL      *This,
  IN EFI_RNG_ALGORITHM     *RNGAlgorithm    OPTIONAL,
  IN UINTN                 RNGValueLength,
  OUT UINT8                *RNGValue
  )
{
  UINTN   Index;
  UINTN   Chunk;
  UINT64  Rand;
  UINT8   *FuzzData;
  BOOLEAN AlgorithmFound;
  UINTN   AlgIdx;

  DEBUG ((DEBUG_INFO, "MockRng: GetRNG Length=%u\n", (UINT32)RNGValueLength));

  if (This == NULL || RNGValue == NULL || RNGValueLength == 0) {
    return EFI_INVALID_PARAMETER;
  }

  //
  // Validate RNGAlgorithm if specified
  //
  if (RNGAlgorithm != NULL) {
    AlgorithmFound = FALSE;
    for (AlgIdx = 0; AlgIdx < ARRAY_SIZE (mSupportedAlgorithms); AlgIdx++) {
      if (CompareGuid (RNGAlgorithm, &mSupportedAlgorithms[AlgIdx])) {
        AlgorithmFound = TRUE;
        break;
      }
    }
    if (!AlgorithmFound) {
      DEBUG ((DEBUG_WARN, "MockRng: Unsupported algorithm requested\n"));
      return EFI_UNSUPPORTED;
    }
  }

  //
  // If fuzz context is available, use fuzz data
  //
  {
    MOCK_FUZZ_CONTEXT  *Ctx = ResolveContext ();
    if (Ctx != NULL) {
      FuzzData = MockFuzzContextConsume (Ctx, RNGValueLength);
      if (FuzzData != NULL) {
        CopyMem (RNGValue, FuzzData, RNGValueLength);
        DEBUG ((DEBUG_INFO, "MockRng: Returned %u bytes from fuzz context\n",
                (UINT32)RNGValueLength));
        return EFI_SUCCESS;
      }
      //
      // If fuzz buffer exhausted, fall back to PRNG but log warning
      //
      DEBUG ((DEBUG_WARN, "MockRng: Fuzz context exhausted, using PRNG\n"));
    }
  }

  //
  // Use deterministic PRNG — advance by Chunk bytes each iteration
  //
  for (Index = 0; Index < RNGValueLength; Index += Chunk) {
    Rand = PrngNext ();
    Chunk = (RNGValueLength - Index) >= 8 ? 8 : (RNGValueLength - Index);
    CopyMem (&RNGValue[Index], &Rand, Chunk);
  }

  DEBUG ((DEBUG_INFO, "MockRng: Returned %u bytes from PRNG\n",
          (UINT32)RNGValueLength));
  return EFI_SUCCESS;
}

//=============================================================================
// State Reset
//=============================================================================

/**
  Reset mock state between fuzz iterations.
  Restores the PRNG seed to default. Per-protocol fuzz context is
  cleared by FuzzContextLib's own reset.
**/
STATIC
VOID
EFIAPI
ResetState (
  VOID
  )
{
  DEBUG ((DEBUG_INFO, "MockRng: ResetState\n"));
  mPrngState = 0x12345678ABCDEF01ULL;
}

//=============================================================================
// Test Helpers (accessed via extern)
//=============================================================================

//
// ---- Test-only helpers (accessed via extern in test files) ----
//

/**
  Override the PRNG seed for deterministic test output.

  @param[in] Seed  New xorshift64* state value.
**/
VOID
EFIAPI
MockRngSetSeed (
  IN UINT64  Seed
  )
{
  DEBUG ((DEBUG_INFO, "MockRng: SetSeed=0x%llx\n", Seed));
  mPrngState = Seed;
}

//=============================================================================
// Library Constructor
//=============================================================================

/**
  Library constructor - initialize the mock protocol.

  @retval RETURN_SUCCESS  Always succeeds
**/
RETURN_STATUS
EFIAPI
MockgEfiRngProtocolGuidConstructor (
  VOID
  )
{
  if ((gBS == NULL) || (gFuzzHandle == NULL)) {
    DEBUG ((DEBUG_WARN, "MockgEfiRngProtocolGuid: gBS or gFuzzHandle is NULL\n"));
    return RETURN_SUCCESS;
  }

  DEBUG ((DEBUG_INFO, "MockgEfiRngProtocolGuid: Constructor\n"));

  //
  // Initialize Protocol
  //
  mMockRngProtocol.GetInfo = MockRngGetInfo;
  mMockRngProtocol.GetRNG  = MockRngGetRNG;

  ResetState ();
  MockProtocolRegisterReset (ResetState);

  //
  // Install the mock protocol on gFuzzHandle so target code can discover
  // it via gBS->OpenProtocol(gFuzzHandle, &gEfiRngProtocolGuid, ...)
  //
  {
    EFI_STATUS  Status;

    Status = gBS->InstallProtocolInterface (
                    &gFuzzHandle,
                    &gEfiRngProtocolGuid,
                    EFI_NATIVE_INTERFACE,
                    &mMockRngProtocol
                    );
    DEBUG ((DEBUG_INFO, "MockgEfiRngProtocolGuid: InstallProtocolInterface on gFuzzHandle: %r\n", Status));
    if (EFI_ERROR (Status)) {
      return RETURN_DEVICE_ERROR;
    }
  }

  DEBUG ((DEBUG_INFO, "MockgEfiRngProtocolGuid: Constructor complete\n"));
  return RETURN_SUCCESS;
}
