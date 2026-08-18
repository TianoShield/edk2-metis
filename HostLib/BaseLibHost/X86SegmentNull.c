/** @file X86SegmentNull.c
  IA-32/x64 segment register stubs for host-based fuzzing.

  AUDIT NOTES (HBFAplus host-fuzzing review):
  FIXED — all functions previously called ASSERT(FALSE) which crashes the
  fuzzer.  Segment registers are meaningless on a Linux userspace host.
  Read functions now return 0 (safe default); write is a no-op.

  Copyright (c) 2006 - 2008, Intel Corporation. All rights reserved.<BR>
  SPDX-License-Identifier: BSD-2-Clause-Patent
**/

#include <Library/BaseLib.h>
#include <Library/DebugLib.h>

/** Reads CS.  AUDIT: returns 0 (no-op stub). **/
UINT16 EFIAPI AsmReadCs (VOID) { return 0; }

/** Reads DS.  AUDIT: returns 0 (no-op stub). **/
UINT16 EFIAPI AsmReadDs (VOID) { return 0; }

/** Reads ES.  AUDIT: returns 0 (no-op stub). **/
UINT16 EFIAPI AsmReadEs (VOID) { return 0; }

/** Reads FS.  AUDIT: returns 0 (no-op stub). **/
UINT16 EFIAPI AsmReadFs (VOID) { return 0; }

/** Reads GS.  AUDIT: returns 0 (no-op stub). **/
UINT16 EFIAPI AsmReadGs (VOID) { return 0; }

/** Reads SS.  AUDIT: returns 0 (no-op stub). **/
UINT16 EFIAPI AsmReadSs (VOID) { return 0; }

/** Reads TR.  AUDIT: returns 0 (no-op stub). **/
UINT16 EFIAPI AsmReadTr (VOID) { return 0; }

/** Writes TR.  AUDIT: no-op stub. **/
VOID EFIAPI AsmWriteTr (IN UINT16 Selector) { }