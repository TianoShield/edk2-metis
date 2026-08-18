/** @file
  Permissive BaseCryptLib stub for HBFA fuzz harnesses.

  ============================================================================
  WHY THIS LIBRARY EXISTS
  ============================================================================

  HBFA fuzz harnesses run real EDK2 driver / library code on a Linux host
  under AFL++ + ASan.  Many security-sensitive UEFI components (Secure Boot,
  signed capsule, TPM measured boot, certdb / Pkcs7 / X.509 parsers) call
  into BaseCryptLib for hashing, signature verification, RSA, X.509 parsing.

  When you wire those targets into HBFA you have only three options for the
  BaseCryptLib resolution:

    (a) CryptoPkg/Library/BaseCryptLib/BaseCryptLib.inf
        --- the real one.  CANNOT BE USED by HBFA host harnesses because:
          * Pulls OpensslLib + IntrinsicLib + SysCall/CrtWrapper.c, which
            redefine memcpy / memset / errno / FILE etc. -- collides with
            the host glibc that AFL/ASan link against.
          * Pulls NASM-assembled CPU-feature stubs (AsmCpuid, RdRand) which
            HBFA's host build flow doesn't assemble.
          * The minimal OpensslLib.inf is missing EC / X.509 ASN.1; using
            OpensslLibFull.inf needs OpenSSL's perl-driven Configure step
            that is not wired into HBFA's GCC5/AFL flow.
          * Real signature verification BLOCKS the fuzzer at signature-check
            time, so the parser code we want fuzzed is unreachable.
        See the TlsDxe SKIPPED comment block in HBFAplus.dsc for the
        canonical write-up of these constraints.

    (b) CryptoPkg/Library/BaseCryptLibNull/BaseCryptLibNull.inf
        Builds, but every entry calls ASSERT(FALSE) and aborts.  Targets
        like AuthVariableLib then ASSERT inside their *_Initialize() during
        ProcessLibraryConstructorList -- the harness never even reaches
        RunTestHarness.  (Observed: TestAuthVariableLib pinned at 337
        edges / 0 crashes regardless of input.)

    (c) THIS FILE.  A permissive stub that:
          * Builds against base host libs only (no OpenSSL, no CRT).
          * Implements every BaseCryptLib symbol any current or anticipated
            HBFA harness might call, returning success-shaped values.
          * Produces input-dependent (but NOT cryptographically secure)
            digests so callers that compare/dedupe/key on hash values
            still distinguish distinct inputs.
        Result on TestAuthVariableLib: 337 -> 613 edges (+82%), 6 -> 39
        corpus, 27 reachable parser bugs surfaced.

  ============================================================================
  CORRECTNESS MODEL -- what bugs this stub can and cannot find
  ============================================================================

  Bugs found under this stub are PRE-CRYPTO bugs: parsing, length
  arithmetic, state-machine confusion, structure traversal -- reachable by
  any caller that can submit fuzzer-controlled bytes to a crypto-consuming
  API.  Cryptographic-bypass research (forging signatures, MitM) requires
  real OpenSSL and is out of scope for HBFA host fuzzing.

  Per-API contract:

    Hashing  (Md5, Sha1, Sha256, Sha384, Sha512, Sm3 families):
      - GetContextSize: returns a fixed 256-byte size that comfortably
        exceeds any real OpenSSL context.  Callers that allocate this much
        will be safe with any future hash flavour we add too.
      - Init / Update / Final / HashAll: succeed iff non-NULL pointers.
      - Output digest is FNV-1a-64 of all input bytes, expanded to the
        requested digest length by salted re-folding.  This means:
            equal input  -> equal digest (caller equality checks work)
            distinct in  -> almost-always distinct digest (caller dedup,
                            cert-cache lookup, replay-detection still
                            distinguish inputs)
        The digest is OBVIOUSLY non-cryptographic; no caller can mistakenly
        rely on it for security.

    PKCS#7 (Pkcs7Verify, Pkcs7GetSigners, Pkcs7FreeSigners,
            VerifyEKUsInPkcs7Signature):
      - Verify always returns TRUE for non-NULL/non-empty inputs.
      - GetSigners hands back a 1-byte placeholder cert + trusted cert.

    X.509 (X509GetTBSCert, X509GetCommonName):
      - GetTBSCert hands back the input verbatim as the "TBS" region.
      - GetCommonName returns the constant string "HBFA-Stub".

    RSA (RsaNew, RsaFree, RsaGetPublicKeyFromX509, RsaPkcs1Verify):
      - Opaque-pointer marker; verify accepts any non-empty signature.

  ============================================================================
  HOW TO ADD MORE STUBS
  ============================================================================

  When a new harness pulls in a BaseCryptLib symbol that's not implemented
  here, the link fails with `undefined reference to <Symbol>`.  EXTEND THIS
  FILE -- do not fork a parallel stub.  Match the upstream signature from
  CryptoPkg/Include/Library/BaseCryptLib.h, return a success-shaped value
  if all pointers are non-NULL and sizes positive, and add a one-line
  comment explaining what the stub deliberately does NOT model.

  ============================================================================
  WHEN NOT TO USE THIS STUB
  ============================================================================

  Do not use this stub for harnesses that need genuine cryptographic
  semantics, e.g.:
    - TPM PCR-extend chains where downstream attestation logic depends on
      SHA-256 collision-resistance.
    - Crypto-protocol bypass research (would require real OpenSSL).
    - Tests that compare a stub-produced digest against a digest computed
      by a different, real implementation.

  Copyright (c) 2026 TianoShield Contributors.
  SPDX-License-Identifier: BSD-2-Clause-Patent
**/

#include <Uefi.h>
#include <Library/BaseLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/DebugLib.h>
#include <Library/BaseCryptLib.h>

//
// ============================================================================
// Hash context layout
// ============================================================================
//
// All hash flavours share a single context layout so we can dispatch
// generically and keep this file small.  256 bytes comfortably exceeds any
// real OpenSSL context, so callers that AllocatePool(GetContextSize()) get
// a buffer that the real lib would also have been happy with.  Some EDK2
// callers reuse a single buffer with multiple hash flavours after their own
// size check -- the fixed size keeps that pattern safe.
//

#define STUB_CTX_MAGIC  0x48425354          // 'HBST'
#define STUB_CTX_SIZE   256

typedef struct {
  UINT32  Magic;
  UINT32  DigestLen;     // requested output size (caller-flavoured)
  UINT64  Accumulator;   // FNV-1a-64 running state
  UINT64  ByteCount;     // total bytes folded in (mixed into output)
} STUB_HASH_CTX;

//
// FNV-1a-64.  Chosen because it is:
//   - tiny (no tables, no heap), portable, deterministic;
//   - input-dependent, so distinct inputs almost always produce distinct
//     digests -- this matters for callers that key/dedup/compare hashes
//     (CertDb cache lookups, replay-detection, PCR-extend chains);
//   - obviously NOT cryptographically secure, so no caller can mistakenly
//     rely on it for security.
//
#define FNV1A64_OFFSET  0xCBF29CE484222325ULL
#define FNV1A64_PRIME   0x00000100000001B3ULL

STATIC
UINT64
Fnv1a64Update (
  IN UINT64       State,
  IN CONST VOID  *Data,
  IN UINTN        Len
  )
{
  CONST UINT8  *P;
  UINTN        I;

  P = (CONST UINT8 *)Data;
  for (I = 0; I < Len; I++) {
    State ^= P[I];
    State *= FNV1A64_PRIME;
  }

  return State;
}

//
// Spread a 64-bit FNV state into an arbitrary-length digest by repeated
// application of FNV-1a using a per-byte salt.  Yields distinct,
// deterministic bytes across the full digest length, so even truncated
// comparisons (first 4 bytes etc.) distinguish distinct inputs.
//
STATIC
VOID
ExpandStateToDigest (
  IN  UINT64  State,
  IN  UINT64  ByteCount,
  OUT UINT8   *Digest,
  IN  UINTN   DigestLen
  )
{
  UINTN  I;
  UINT64 S;
  UINT8  Salt;

  S = State ^ ByteCount;
  for (I = 0; I < DigestLen; I++) {
    Salt      = (UINT8)I;
    S         = Fnv1a64Update (S, &Salt, 1);
    Digest[I] = (UINT8)(S & 0xFF);
  }
}

STATIC
BOOLEAN
StubHashInit (
  OUT VOID    *Ctx,
  IN  UINT32  DigestLen
  )
{
  STUB_HASH_CTX  *H;

  if (Ctx == NULL) {
    return FALSE;
  }

  H              = (STUB_HASH_CTX *)Ctx;
  H->Magic       = STUB_CTX_MAGIC;
  H->DigestLen   = DigestLen;
  H->Accumulator = FNV1A64_OFFSET;
  H->ByteCount   = 0;
  return TRUE;
}

STATIC
BOOLEAN
StubHashDuplicate (
  IN  CONST VOID  *Src,
  OUT VOID        *Dst
  )
{
  if ((Src == NULL) || (Dst == NULL)) {
    return FALSE;
  }

  CopyMem (Dst, Src, STUB_CTX_SIZE);
  return TRUE;
}

STATIC
BOOLEAN
StubHashUpdate (
  IN OUT VOID        *Ctx,
  IN     CONST VOID  *Data,
  IN     UINTN       DataSize
  )
{
  STUB_HASH_CTX  *H;

  if ((Ctx == NULL) || ((Data == NULL) && (DataSize != 0))) {
    return FALSE;
  }

  H              = (STUB_HASH_CTX *)Ctx;
  H->Accumulator = Fnv1a64Update (H->Accumulator, Data, DataSize);
  H->ByteCount  += DataSize;
  return TRUE;
}

STATIC
BOOLEAN
StubHashFinal (
  IN OUT VOID    *Ctx,
  OUT    UINT8   *HashValue,
  IN     UINT32  DigestLen
  )
{
  STUB_HASH_CTX  *H;

  if ((Ctx == NULL) || (HashValue == NULL)) {
    return FALSE;
  }

  H = (STUB_HASH_CTX *)Ctx;
  ExpandStateToDigest (H->Accumulator, H->ByteCount, HashValue, DigestLen);
  return TRUE;
}

STATIC
BOOLEAN
StubHashAll (
  IN  CONST VOID  *Data,
  IN  UINTN       DataSize,
  OUT UINT8       *HashValue,
  IN  UINT32      DigestLen
  )
{
  UINT64  State;

  if ((HashValue == NULL) || ((Data == NULL) && (DataSize != 0))) {
    return FALSE;
  }

  State = Fnv1a64Update (FNV1A64_OFFSET, Data, DataSize);
  ExpandStateToDigest (State, DataSize, HashValue, DigestLen);
  return TRUE;
}

//
// ============================================================================
// MD5 / SHA-1 / SHA-256 / SHA-384 / SHA-512 / SM3 wrappers
// ============================================================================
//
// All thin wrappers around StubHash* using the appropriate digest length.
// We provide every common flavour because different consumers in EDK2 use
// different hash families:
//   * AuthVariableLib  - SHA-256 / SHA-384 / SHA-512
//   * Tcg2 / Measured  - SHA-1, SHA-256, SHA-384, SHA-512, SM3
//   * Pkcs7 / X.509    - SHA-1 fallback paths
//   * Variable replay  - MD5 (legacy)
// Adding all flavours up front costs a few lines and makes this stub
// reusable by future harnesses without re-linking work.
//

#define HASH_THUNKS(Name, DigestSize)                                                       \
  UINTN   EFIAPI Name##GetContextSize (VOID)                                                \
  { return STUB_CTX_SIZE; }                                                                 \
  BOOLEAN EFIAPI Name##Init      (OUT VOID *Ctx)                                            \
  { return StubHashInit (Ctx, (DigestSize)); }                                              \
  BOOLEAN EFIAPI Name##Duplicate (IN CONST VOID *S, OUT VOID *D)                            \
  { return StubHashDuplicate (S, D); }                                                      \
  BOOLEAN EFIAPI Name##Update    (IN OUT VOID *Ctx, IN CONST VOID *Data, IN UINTN Len)      \
  { return StubHashUpdate (Ctx, Data, Len); }                                               \
  BOOLEAN EFIAPI Name##Final     (IN OUT VOID *Ctx, OUT UINT8 *Hash)                        \
  { return StubHashFinal (Ctx, Hash, (DigestSize)); }                                       \
  BOOLEAN EFIAPI Name##HashAll   (IN CONST VOID *Data, IN UINTN Len, OUT UINT8 *Hash)       \
  { return StubHashAll (Data, Len, Hash, (DigestSize)); }

HASH_THUNKS (Md5,    MD5_DIGEST_SIZE)
HASH_THUNKS (Sha1,   SHA1_DIGEST_SIZE)
HASH_THUNKS (Sha256, SHA256_DIGEST_SIZE)
HASH_THUNKS (Sha384, SHA384_DIGEST_SIZE)
HASH_THUNKS (Sha512, SHA512_DIGEST_SIZE)
HASH_THUNKS (Sm3,    SM3_256_DIGEST_SIZE)

//
// ============================================================================
// PKCS#7 - accept everything (so the parser code around it gets fuzzed).
// ============================================================================
//

BOOLEAN
EFIAPI
Pkcs7Verify (
  IN  CONST UINT8  *P7Data,
  IN  UINTN        P7Length,
  IN  CONST UINT8  *TrustedCert,
  IN  UINTN        CertLength,
  IN  CONST UINT8  *InData,
  IN  UINTN        DataLength
  )
{
  if ((P7Data == NULL) || (P7Length == 0) ||
      (TrustedCert == NULL) || (CertLength == 0) ||
      ((InData == NULL) && (DataLength != 0)))
  {
    return FALSE;
  }

  return TRUE;
}

RETURN_STATUS
EFIAPI
VerifyEKUsInPkcs7Signature (
  IN  CONST UINT8   *Pkcs7Signature,
  IN  CONST UINT32  SignatureSize,
  IN  CONST CHAR8   *RequiredEKUs[],
  IN  CONST UINT32  RequiredEKUsSize,
  IN  BOOLEAN       RequireAllPresent
  )
{
  (VOID)RequireAllPresent;
  if ((Pkcs7Signature == NULL) || (SignatureSize == 0) ||
      (RequiredEKUs == NULL) || (RequiredEKUsSize == 0))
  {
    return RETURN_INVALID_PARAMETER;
  }

  return RETURN_SUCCESS;
}

BOOLEAN
EFIAPI
Pkcs7GetSigners (
  IN  CONST UINT8  *P7Data,
  IN  UINTN        P7Length,
  OUT UINT8        **CertStack,
  OUT UINTN        *StackLength,
  OUT UINT8        **TrustedCert,
  OUT UINTN        *CertLength
  )
{
  UINT8  *Buf;

  if ((P7Data == NULL) || (P7Length == 0) ||
      (CertStack == NULL) || (StackLength == NULL) ||
      (TrustedCert == NULL) || (CertLength == NULL))
  {
    return FALSE;
  }

  //
  // Hand back a single 1-byte placeholder cert + trusted cert.  The X509
  // stubs accept anything, so callers don't parse these further.
  //
  Buf = AllocateZeroPool (1);
  if (Buf == NULL) {
    return FALSE;
  }

  *CertStack   = Buf;
  *StackLength = 1;

  Buf = AllocateZeroPool (1);
  if (Buf == NULL) {
    return FALSE;
  }

  *TrustedCert = Buf;
  *CertLength  = 1;
  return TRUE;
}

VOID
EFIAPI
Pkcs7FreeSigners (
  IN UINT8  *Certs
  )
{
  if (Certs != NULL) {
    FreePool (Certs);
  }
}

//
// ============================================================================
// X.509 - accept any non-empty cert, return tiny canned data.
// ============================================================================
//

BOOLEAN
EFIAPI
X509GetTBSCert (
  IN  CONST UINT8  *Cert,
  IN  UINTN        CertSize,
  OUT UINT8        **TBSCert,
  OUT UINTN        *TBSCertSize
  )
{
  if ((Cert == NULL) || (CertSize == 0) ||
      (TBSCert == NULL) || (TBSCertSize == NULL))
  {
    return FALSE;
  }

  //
  // Return the input verbatim as the "TBS cert" -- callers hash it and
  // our hash stub doesn't care about contents.  Note the lifetime is the
  // caller's; we do not allocate.
  //
  *TBSCert     = (UINT8 *)Cert;
  *TBSCertSize = CertSize;
  return TRUE;
}

RETURN_STATUS
EFIAPI
X509GetCommonName (
  IN      CONST UINT8  *Cert,
  IN      UINTN        CertSize,
  OUT     CHAR8        *CommonName    OPTIONAL,
  IN OUT  UINTN        *CommonNameSize
  )
{
  CONST CHAR8  *Name = "HBFA-Stub";
  UINTN        Need;

  if ((Cert == NULL) || (CertSize == 0) || (CommonNameSize == NULL)) {
    return RETURN_INVALID_PARAMETER;
  }

  Need = AsciiStrLen (Name) + 1;

  if ((CommonName == NULL) || (*CommonNameSize < Need)) {
    *CommonNameSize = Need;
    return RETURN_BUFFER_TOO_SMALL;
  }

  AsciiStrCpyS (CommonName, *CommonNameSize, Name);
  *CommonNameSize = Need;
  return RETURN_SUCCESS;
}

//
// ============================================================================
// RSA - opaque-context stubs.
// ============================================================================
//
// Targets like AuthService.c call RsaGetPublicKeyFromX509() then RsaFree().
// They don't actually verify the RSA signature themselves (Pkcs7Verify
// already returned TRUE above), but the ctor / dtor pair must succeed or
// the cert-import flow short-circuits and fuzzer coverage drops.
//

#define STUB_RSA_MARKER  ((VOID *)(UINTN)0x0BADC0DE0BADC0DEULL)

VOID *
EFIAPI
RsaNew (
  VOID
  )
{
  return STUB_RSA_MARKER;
}

VOID
EFIAPI
RsaFree (
  IN VOID  *RsaContext
  )
{
  (VOID)RsaContext;
}

BOOLEAN
EFIAPI
RsaGetPublicKeyFromX509 (
  IN   CONST UINT8  *Cert,
  IN   UINTN        CertSize,
  OUT  VOID         **RsaContext
  )
{
  if ((Cert == NULL) || (CertSize == 0) || (RsaContext == NULL)) {
    return FALSE;
  }

  *RsaContext = STUB_RSA_MARKER;
  return TRUE;
}

BOOLEAN
EFIAPI
RsaPkcs1Verify (
  IN  VOID         *RsaContext,
  IN  CONST UINT8  *MessageHash,
  IN  UINTN        HashSize,
  IN  CONST UINT8  *Signature,
  IN  UINTN        SigSize
  )
{
  return (RsaContext != NULL) && (MessageHash != NULL) && (HashSize > 0) &&
         (Signature != NULL) && (SigSize > 0);
}
