/** @file DxeServicesTableLibHost.c
  Host-side DxeServicesTableLib implementation for HBFAplus fuzzing environment.

  AUDIT NOTES (HBFAplus host-fuzzing review):
  ============================================

  This library provides the DXE Services Table (gDS) for host-based rehosting.
  Any edk2 DXE driver that uses gDS->AddMemorySpace, gDS->GetMemorySpaceMap,
  or any other DXE service depends on this library.

  The GCD (Global Coherency Domain) map implementation is a direct copy from
  the real DxeCore (MdeModulePkg/Core/Dxe/Gcd/Gcd.c).  It provides a fully
  functional memory and I/O space map with real linked-list management, making
  it suitable for fuzzing any component that depends on GCD services.

  Services provided via gDS (18 EFI_DXE_SERVICES functions):

  GCD Memory Space Services (fully functional, from Gcd.c):
    1.  CoreAddMemorySpace          — Add memory region to GCD map
    2.  CoreAllocateMemorySpace     — Allocate from GCD memory map
    3.  CoreFreeMemorySpace         — Free allocated GCD memory
    4.  CoreRemoveMemorySpace       — Remove memory from GCD map
    5.  CoreGetMemorySpaceDescriptor — Query descriptor for address
    6.  CoreSetMemorySpaceAttributes — Set memory attributes
    7.  CoreGetMemorySpaceMap       — Retrieve full memory space map
    8.  CoreSetMemorySpaceCapabilities — Set memory capabilities

  GCD I/O Space Services (fully functional, from Gcd.c):
    9.  CoreAddIoSpace              — Add I/O region to GCD map
    10. CoreAllocateIoSpace         — Allocate from GCD I/O map
    11. CoreFreeIoSpace             — Free allocated I/O space
    12. CoreRemoveIoSpace           — Remove I/O from GCD map
    13. CoreGetIoSpaceDescriptor    — Query I/O descriptor
    14. CoreGetIoSpaceMap           — Retrieve full I/O space map

  Dispatcher Services (stubs — not meaningful for host fuzzing):
    15. CoreDispatcher              — Returns EFI_UNSUPPORTED (no-op)
    16. CoreSchedule                — Returns EFI_UNSUPPORTED (no-op)
    17. CoreTrust                   — Returns EFI_UNSUPPORTED (no-op)

  Firmware Volume Service (stub):
    18. CoreProcessFirmwareVolume   — Returns EFI_UNSUPPORTED (no-op)

  CRASH FIX — Removed ASSERT(FALSE) from stubs:
  -----------------------------------------------
  The original code used ASSERT(FALSE) in all stub functions (CoreDispatcher,
  CoreSchedule, CoreTrust, CoreProcessFirmwareVolume, CoreAddMemoryDescriptor,
  CoreUpdateMemoryAttributes).  Since DebugAssert calls exit(1), any fuzz target
  that triggered these paths would hard-crash, killing the fuzzer process.

  Fix: All stubs are now safe no-ops that return EFI_UNSUPPORTED (or are void
  no-ops).  This allows fuzzing to continue even when code paths touch
  dispatcher or FV services that have no host equivalent.

  IMPORTANT: CoreAddMemoryDescriptor and CoreUpdateMemoryAttributes are
  called by the GCD code itself (CoreAddMemorySpace and
  CoreSetMemorySpaceCapabilities respectively).  Making them no-ops means
  that adding system memory won't create memory type descriptors, and
  setting capabilities won't update page attributes.  This is acceptable
  for host fuzzing where we don't have real page tables.

  Constructor:
    DxeServicesTableLibConstructor — Initializes GCD maps with:
      - 48-bit memory address space (256 TB, standard x86-64)
      - 36-bit I/O address space (64 GB, standard x86-64)

  External dependencies (provided by UefiBootServicesTableLibHost):
    - CoreAcquireLock / CoreReleaseLock (lock stubs)
    - CoreRaiseTpl / CoreRestoreTpl (TPL stubs)
    - CoreFreePool (calls free())
    - gDxeCoreImageHandle (image handle)

  Copyright (c) 2006 - 2018, Intel Corporation. All rights reserved.<BR>
  Copyright (c) 2025, HBFAplus Contributors. All rights reserved.
  SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include "Gcd.h"

EFI_STATUS
CoreInitializeGcdServices (
  IN UINT8                              SizeOfMemorySpace,
  IN UINT8                              SizeOfIoSpace
  );

extern EFI_DXE_SERVICES mDxeServices;

//
// Cache copy of the DXE Services Table
//
EFI_DXE_SERVICES  *gDS      = &mDxeServices;

BOOLEAN mOnGuarding = FALSE;
EFI_CPU_ARCH_PROTOCOL                    *gCpu = NULL;

/**
  DXE Dispatcher stub — not meaningful in host fuzzing environment.

  The real DXE Dispatcher loads and starts PE images from firmware volumes.
  In host fuzzing there are no firmware volumes or DXE driver images to
  dispatch, so this is a safe no-op.

  @retval EFI_UNSUPPORTED  Always — dispatching is not supported on host.
**/
EFI_STATUS
EFIAPI
CoreDispatcher (
  VOID
  )
{
  //
  // AUDIT: Removed ASSERT(FALSE) — was causing exit(1) during fuzzing.
  // No-op stub; the host environment has no firmware volumes to dispatch.
  //
  return EFI_UNSUPPORTED;
}

/**
  Schedule driver stub — not meaningful in host fuzzing environment.

  The real implementation searches the discovered driver list and clears
  the Schedule-On-Request (SOR) bit.  In host fuzzing there is no driver
  discovery infrastructure.

  @param[in] FirmwareVolumeHandle  Ignored.
  @param[in] DriverName            Ignored.

  @retval EFI_UNSUPPORTED  Always — scheduling is not supported on host.
**/
EFI_STATUS
EFIAPI
CoreSchedule (
  IN  EFI_HANDLE  FirmwareVolumeHandle,
  IN  EFI_GUID    *DriverName
  )
{
  //
  // AUDIT: Removed ASSERT(FALSE) — was causing exit(1) during fuzzing.
  //
  return EFI_UNSUPPORTED;
}


/**
  Trust driver stub — not meaningful in host fuzzing environment.

  The real implementation promotes an untrusted driver back to the
  scheduled state.  In host fuzzing there is no trust infrastructure.

  @param[in] FirmwareVolumeHandle  Ignored.
  @param[in] DriverName            Ignored.

  @retval EFI_UNSUPPORTED  Always — trust management is not supported on host.
**/
EFI_STATUS
EFIAPI
CoreTrust (
  IN  EFI_HANDLE  FirmwareVolumeHandle,
  IN  EFI_GUID    *DriverName
  )
{
  //
  // AUDIT: Removed ASSERT(FALSE) — was causing exit(1) during fuzzing.
  //
  return EFI_UNSUPPORTED;
}

/**
  Process firmware volume stub — not meaningful in host fuzzing environment.

  The real implementation parses an FV header and installs an FVB protocol.
  In host fuzzing there are no real firmware volumes to process.

  @param[in]  FvHeader           Ignored.
  @param[in]  Size               Ignored.
  @param[out] FVProtocolHandle   Set to NULL if non-NULL.

  @retval EFI_UNSUPPORTED  Always — FV processing is not supported on host.
**/
EFI_STATUS
EFIAPI
CoreProcessFirmwareVolume (
  IN VOID                             *FvHeader,
  IN UINTN                            Size,
  OUT EFI_HANDLE                      *FVProtocolHandle
  )
{
  //
  // AUDIT: Removed ASSERT(FALSE) — was causing exit(1) during fuzzing.
  // If caller provided an output handle, zero it to prevent use of garbage.
  //
  if (FVProtocolHandle != NULL) {
    *FVProtocolHandle = NULL;
  }
  return EFI_UNSUPPORTED;
}

/**
  Add a memory descriptor to the EFI memory map — no-op stub.

  The real DxeCore maintains a separate memory map (from the GCD map) that
  tracks EFI_MEMORY_TYPE for each page range.  In the host fuzzing
  environment we use malloc()/free() for memory allocation, so there is no
  real page-level memory map to maintain.

  This function is called by CoreAddMemorySpace() when system memory is
  added.  Making it a no-op means memory type tracking is skipped, which
  is acceptable for fuzzing (no GetMemoryMap consumer cares about types).

  AUDIT: Removed ASSERT(FALSE) — was causing exit(1) when any edk2 code
  called gDS->AddMemorySpace(EfiGcdMemoryTypeSystemMemory, ...).

  @param[in] Type           Memory type (ignored).
  @param[in] Start          Start address (ignored).
  @param[in] NumberOfPages  Page count (ignored).
  @param[in] Attribute      Attributes (ignored).
**/
VOID
CoreAddMemoryDescriptor (
  IN EFI_MEMORY_TYPE       Type,
  IN EFI_PHYSICAL_ADDRESS  Start,
  IN UINT64                NumberOfPages,
  IN UINT64                Attribute
  )
{
  //
  // No-op: host environment uses malloc/free, not page-level descriptors.
  //
}

/**
  Update memory attributes in the EFI memory map — no-op stub.

  Called by CoreSetMemorySpaceCapabilities() after updating GCD capabilities.
  The real DxeCore would update page table attributes here.  In the host
  environment there are no real page tables, so this is a safe no-op.

  AUDIT: Removed ASSERT(FALSE) — was causing exit(1) when any edk2 code
  called gDS->SetMemorySpaceCapabilities().

  @param[in] Start           Start address (ignored).
  @param[in] NumberOfPages   Page count (ignored).
  @param[in] NewAttributes   New attributes (ignored).
**/
VOID
CoreUpdateMemoryAttributes (
  IN EFI_PHYSICAL_ADDRESS  Start,
  IN UINT64                NumberOfPages,
  IN UINT64                NewAttributes
  )
{
  //
  // No-op: host environment has no real page tables to update.
  //
}

/**
  Library constructor — initializes the GCD memory and I/O space maps.

  Called automatically during library initialization (autogen constructor list).
  Sets up:
    - 48-bit memory address space (256 TB — standard x86-64 physical)
    - 36-bit I/O address space (64 GB — standard x86-64 I/O port range)

  @retval EFI_SUCCESS  GCD maps successfully initialized.
**/
EFI_STATUS
EFIAPI
DxeServicesTableLibConstructor (
  VOID
  )
{
  return CoreInitializeGcdServices (48, 36);
}