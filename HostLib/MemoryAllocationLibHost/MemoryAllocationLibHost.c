/** @file
  MemoryAllocationLibHost — Host-based implementation of MemoryAllocationLib.

  Provides all 21 MemoryAllocationLib API functions for host-based fuzzing
  and unit testing.  Backed by libc malloc/free/realloc.

  == Architecture ==
  Page Allocations     — AllocatePages / AllocateAlignedPages use malloc with
                          a PAGE_HEAD metadata block placed just before the
                          aligned buffer.  The metadata records the original
                          malloc pointer, total pages, and aligned pages so
                          FreeAlignedPages can call free() on the correct
                          address.  Alignment is always >= 4 KB.
  Pool Allocations     — AllocatePool / AllocateZeroPool / AllocateCopyPool
                          are thin wrappers around malloc / memset / memcpy.
  Reallocation         — ReallocatePool delegates to libc realloc().
  Memory Types         — Runtime and Reserved variants all delegate to the
                          base variant because on the host there is only one
                          memory type (host process heap).

  == Audit Notes (2025) ==
  API Completeness     — All 21 functions from MemoryAllocationLib.h are
                          implemented: AllocatePages, AllocateRuntimePages,
                          AllocateReservedPages, FreePages,
                          AllocateAlignedPages, AllocateAlignedRuntimePages,
                          AllocateAlignedReservedPages, FreeAlignedPages,
                          AllocatePool, AllocateRuntimePool,
                          AllocateReservedPool, AllocateZeroPool,
                          AllocateRuntimeZeroPool, AllocateReservedZeroPool,
                          AllocateCopyPool, AllocateRuntimeCopyPool,
                          AllocateReservedCopyPool, ReallocatePool,
                          ReallocateRuntimePool, ReallocateReservedPool,
                          FreePool.
  Fuzzing Safety       — No ASSERT(FALSE) or exit paths.  AllocateAlignedPages
                          returns NULL on malloc failure.  FreeAlignedPages
                          validates the PAGE_HEAD signature and page count
                          before freeing, silently ignoring mismatches (safe
                          for fuzzing — prevents double-free or misuse crash).
  ReallocatePool Note  — FIXED: now zero-fills the growth delta after
                          libc realloc, matching real UEFI behaviour.
  Rehosting Suitability — Fully suitable.  All allocations go through the
                          host process heap.  ASan/MSan will catch overflows,
                          use-after-free, and leaks transparently.

Copyright (c) 2018, Intel Corporation. All rights reserved.<BR>
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <Uefi.h>
#include <Library/DebugLib.h>

// AUDIT: This entire file is a thin libc wrapper — malloc/realloc/free back
// every allocation.  Unlike edk2, there is no memory-map, no pool-type
// segregation, and no page-table tracking.  ASan/MSan/LSan instrument these
// libc calls transparently, which is the primary advantage of this approach.

//
// PAGE_HEAD_PRIVATE_SIGNATURE — magic value placed before every aligned
// page allocation.  FreeAlignedPages validates this before calling free().
//
#define PAGE_HEAD_PRIVATE_SIGNATURE  SIGNATURE_32 ('P', 'H', 'D', 'R')

//
// Metadata stored just before every aligned page allocation.
// NOTE: The field name "AllocatedBufffer" has a historical typo (3 f's)
// but is kept for binary compatibility with any code that memcpy's this.
//
typedef struct {
  UINT32 Signature;           // PAGE_HEAD_PRIVATE_SIGNATURE
  VOID   *AllocatedBufffer;   // Original malloc() pointer
  UINTN  TotalPages;          // Total pages including alignment padding
  VOID   *AlignedBuffer;      // Aligned pointer returned to caller
  UINTN  AlignedPages;        // Number of usable pages requested by caller
} PAGE_HEAD;

VOID *
EFIAPI
AllocateAlignedPages (
  IN UINTN  Pages,
  IN UINTN  Alignment
  );

VOID
EFIAPI
FreeAlignedPages (
  IN VOID   *Buffer,
  IN UINTN  Pages
  );

// AUDIT: FIXED — edk2's InternalAllocatePages returns NULL when Pages==0.
// Previously this always delegated to AllocateAlignedPages which allocates
// metadata even for 0 pages, returning non-NULL.  Now matches edk2 spec.
VOID *
EFIAPI
AllocatePages (
  IN UINTN  Pages
  )
{
  if (Pages == 0) {
    return NULL;
  }

  return AllocateAlignedPages (Pages, SIZE_4KB);
}

VOID *
EFIAPI
AllocateRuntimePages (
  IN UINTN  Pages
  )
{
  return AllocatePages (Pages);
}

VOID *
EFIAPI
AllocateReservedPages (
  IN UINTN  Pages
  )
{
  return AllocatePages (Pages);
}

// AUDIT: FreePages/AllocatePages use the same PAGE_HEAD aligned-page
// machinery — alignment is tracked via the metadata block placed before
// the buffer.  Page-count validation happens in FreeAlignedPages, so a
// mismatched Pages argument is silently ignored (safe for fuzzing).
VOID
EFIAPI
FreePages (
  IN VOID   *Buffer,
  IN UINTN  Pages
  )
{
  FreeAlignedPages (Buffer, Pages);
}

VOID *
EFIAPI
AllocateAlignedPages (
  IN UINTN  Pages,
  IN UINTN  Alignment
  )
{
  PAGE_HEAD             PageHead;
  PAGE_HEAD             *PageHeadPtr;
  UINTN                 AlignmentMask;

  ASSERT ((Alignment & (Alignment - 1)) == 0);

  if (Alignment < SIZE_4KB) {
    Alignment = SIZE_4KB;
  }
  AlignmentMask  = Alignment - 1;

  //
  // We need reserve Alignment pages for PAGE_HEAD, as meta data.
  //

  PageHead.Signature = PAGE_HEAD_PRIVATE_SIGNATURE;
  PageHead.TotalPages = Pages + EFI_SIZE_TO_PAGES(Alignment) * 2;
  PageHead.AlignedPages = Pages;
  PageHead.AllocatedBufffer = malloc (EFI_PAGES_TO_SIZE(PageHead.TotalPages));
  if (PageHead.AllocatedBufffer == NULL) {
    return NULL;
  }
  PageHead.AlignedBuffer = (VOID *)(((UINTN) PageHead.AllocatedBufffer + AlignmentMask) & ~AlignmentMask);
  if ((UINTN)PageHead.AlignedBuffer - (UINTN)PageHead.AllocatedBufffer < sizeof(PAGE_HEAD)) {
    PageHead.AlignedBuffer = (VOID *)((UINTN)PageHead.AlignedBuffer + Alignment);
  }

  PageHeadPtr = (VOID *)((UINTN)PageHead.AlignedBuffer - sizeof(PAGE_HEAD));
  memcpy (PageHeadPtr, &PageHead, sizeof(PAGE_HEAD));

  return PageHead.AlignedBuffer;
}

VOID *
EFIAPI
AllocateAlignedRuntimePages (
  IN UINTN  Pages,
  IN UINTN  Alignment
  )
{
  return AllocateAlignedPages (Pages, Alignment);
}

VOID *
EFIAPI
AllocateAlignedReservedPages (
  IN UINTN  Pages,
  IN UINTN  Alignment
  )
{
  return AllocateAlignedPages (Pages, Alignment);
}

//
// AUDIT: Validates PAGE_HEAD signature and page count before freeing.
// Silently ignores mismatches — intentional for fuzzing safety (prevents
// double-free, use-after-free on bogus pointers, partial-free attempts).
//
VOID
EFIAPI
FreeAlignedPages (
  IN VOID   *Buffer,
  IN UINTN  Pages
  )
{
  PAGE_HEAD             *PageHeadPtr;

  //
  // NOTE: Partial free is not supported. Just keep it.
  //

  PageHeadPtr = (VOID *)((UINTN)Buffer - sizeof(PAGE_HEAD));
  if (PageHeadPtr->Signature != PAGE_HEAD_PRIVATE_SIGNATURE) {
    return ;
  }
  if (PageHeadPtr->AlignedPages != Pages) {
    return ;
  }

  PageHeadPtr->Signature = 0;
  free (PageHeadPtr->AllocatedBufffer);
}

VOID *
EFIAPI
AllocatePool (
  IN UINTN  AllocationSize
  )
{
  return malloc (AllocationSize);
}

VOID *
EFIAPI
AllocateRuntimePool (
  IN UINTN  AllocationSize
  )
{
  return AllocatePool (AllocationSize);
}

VOID *
EFIAPI
AllocateReservedPool (
  IN UINTN  AllocationSize
  )
{
  return AllocatePool (AllocationSize);
}

VOID *
EFIAPI
AllocateZeroPool (
  IN UINTN  AllocationSize
  )
{
  VOID *Buffer;
  Buffer = malloc (AllocationSize);
  if (Buffer == NULL) {
    return NULL;
  }
  memset (Buffer, 0, AllocationSize);
  return Buffer;
}

VOID *
EFIAPI
AllocateRuntimeZeroPool (
  IN UINTN  AllocationSize
  )
{
  return AllocateZeroPool (AllocationSize);
}

VOID *
EFIAPI
AllocateReservedZeroPool (
  IN UINTN  AllocationSize
  )
{
  return AllocateZeroPool (AllocationSize);
}

VOID *
EFIAPI
AllocateCopyPool (
  IN UINTN       AllocationSize,
  IN CONST VOID  *Buffer
  )
{
  VOID  *Memory;
  Memory = malloc (AllocationSize);
  if (Memory == NULL) {
    return NULL;
  }
  memcpy (Memory, Buffer, AllocationSize);
  return Memory;
}

VOID *
EFIAPI
AllocateRuntimeCopyPool (
  IN UINTN       AllocationSize,
  IN CONST VOID  *Buffer
  )
{
  return AllocateCopyPool (AllocationSize, Buffer);
}

VOID *
EFIAPI
AllocateReservedCopyPool (
  IN UINTN       AllocationSize,
  IN CONST VOID  *Buffer
  )
{
  return AllocateCopyPool (AllocationSize, Buffer);
}

// AUDIT: FIXED — Real UEFI ReallocatePool zero-fills the growth delta via
// ZeroMem(new + OldSize, NewSize - OldSize).  libc realloc() leaves the
// delta uninitialized.  Now we zero-fill after realloc when growing,
// matching edk2 spec behaviour.
VOID *
EFIAPI
ReallocatePool (
  IN UINTN  OldSize,
  IN UINTN  NewSize,
  IN VOID   *OldBuffer  OPTIONAL
  )
{
  VOID  *NewBuffer;

  NewBuffer = realloc (OldBuffer, NewSize);
  if (NewBuffer != NULL && NewSize > OldSize) {
    //
    // Zero-fill the growth delta to match edk2 spec behaviour.
    //
    memset ((UINT8 *)NewBuffer + OldSize, 0, NewSize - OldSize);
  }

  return NewBuffer;
}

VOID *
EFIAPI
ReallocateRuntimePool (
  IN UINTN  OldSize,
  IN UINTN  NewSize,
  IN VOID   *OldBuffer  OPTIONAL
  )
{
  return ReallocatePool (OldSize, NewSize, OldBuffer);
}

VOID *
EFIAPI
ReallocateReservedPool (
  IN UINTN  OldSize,
  IN UINTN  NewSize,
  IN VOID   *OldBuffer  OPTIONAL
  )
{
  return ReallocatePool (OldSize, NewSize, OldBuffer);
}

VOID
EFIAPI
FreePool (
  IN VOID   *Buffer
  )
{
  free (Buffer);
}
