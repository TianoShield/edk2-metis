/** @file
  UefiBootServicesTableLibHost - Host-compatible UEFI Boot Services implementation.

  This library provides:
  1. gBS and gST global pointers for UEFI code running on the host
  2. Memory allocation (via libc malloc/free)
  3. Protocol database (handle/protocol registration)
  4. Event/Timer support (mock implementation for fuzzing)

  The event functions (CreateEvent, SetTimer, CloseEvent, SignalEvent, WaitForEvent)
  are fully implemented here to support UEFI drivers that use timers and events.

  Copyright (c) 2018, Intel Corporation. All rights reserved.<BR>
  Copyright (c) 2024, HBFAplus Contributors. All rights reserved.<BR>
  SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include <Uefi.h>
#include <Library/BaseLib.h>
#include <Library/DebugLib.h>
#include <Library/BaseMemoryLib.h>

#include "DxeMain.h"
#include "MockEventHost.h"

extern EFI_BOOT_SERVICES mBootServices;
extern EFI_SYSTEM_TABLE mEfiSystemTableTemplate;

EFI_SYSTEM_TABLE   *gST         = &mEfiSystemTableTemplate;
EFI_BOOT_SERVICES  *gBS         = &mBootServices;
EFI_HANDLE         gImageHandle = NULL;

EFI_HANDLE            gDxeCoreImageHandle = NULL;
EFI_SECURITY2_ARCH_PROTOCOL              *gSecurity2;

//
// Global fuzz handle - all mock protocols are installed on this single handle.
// Mock library constructors call gBS->InstallProtocolInterface(&gFuzzHandle, ...)
// and harness/target code retrieves them via gBS->HandleProtocol(gFuzzHandle, ...).
//
EFI_HANDLE         gFuzzHandle = NULL;

/**
  Allocate pages from the host heap.

  AUDIT: Host implementation uses libc malloc().  The Type parameter
  (AllocateAnyPages / AllocateMaxAddress / AllocateAddress) is ignored
  because we don't manage a real physical memory map.  MemoryType is
  also ignored — all allocations come from the same host heap.

  This is acceptable for fuzzing because UEFI driver code that calls
  AllocatePages only cares about getting a valid buffer, not about the
  physical address placement.

  @param[in]   Type           Allocation type (ignored in host env).
  @param[in]   MemoryType     Memory type (ignored in host env).
  @param[in]   NumberOfPages  Number of 4KB pages to allocate.
  @param[out]  Memory         Receives the base address of the allocation.

  @retval EFI_SUCCESS            Pages allocated.
  @retval EFI_INVALID_PARAMETER  Memory is NULL.
  @retval EFI_OUT_OF_RESOURCES   malloc() failed.
**/
EFI_STATUS
EFIAPI
CoreAllocatePages (
  IN  EFI_ALLOCATE_TYPE     Type,
  IN  EFI_MEMORY_TYPE       MemoryType,
  IN  UINTN                 NumberOfPages,
  OUT EFI_PHYSICAL_ADDRESS  *Memory
  )
{
  VOID *Buffer;
  if (Memory == NULL) {
    return EFI_INVALID_PARAMETER;
  }

  if (NumberOfPages == 0) {
    //
    // UEFI Spec: allocating 0 pages is valid — return a unique pointer.
    // Use 1 byte so malloc() returns a non-NULL unique address.
    //
    Buffer = malloc (1);
  } else {
    Buffer = malloc (EFI_PAGES_TO_SIZE (NumberOfPages));
  }

  if (Buffer == NULL) {
    return EFI_OUT_OF_RESOURCES;
  }
  *Memory = (UINTN)Buffer;
  return EFI_SUCCESS;
}

/**
  Free pages previously allocated by CoreAllocatePages.

  AUDIT: Passes through to libc free().  NumberOfPages is ignored
  because malloc() tracks the allocation size internally.

  @param[in]  Memory         Base address returned by CoreAllocatePages.
  @param[in]  NumberOfPages  Number of pages (ignored — malloc tracks size).

  @retval EFI_SUCCESS            Memory freed.
  @retval EFI_INVALID_PARAMETER  Memory is 0 (NULL pointer).
**/
EFI_STATUS
EFIAPI
CoreFreePages (
  IN EFI_PHYSICAL_ADDRESS  Memory,
  IN UINTN                 NumberOfPages
  )
{
  if (Memory == 0) {
    return EFI_INVALID_PARAMETER;
  }

  free ((VOID *)(UINTN)Memory);
  return EFI_SUCCESS;
}

/**
  Allocate pool memory from the host heap.

  AUDIT: Host implementation uses libc malloc().  PoolType is ignored
  because the host has a single flat heap.

  Per UEFI Spec 7.2, Size=0 is valid and must return a unique non-NULL
  pointer that can later be passed to FreePool.  We handle this by
  bumping Size to 1 so malloc() returns a valid unique address.

  @param[in]   PoolType  Pool type (ignored in host env).
  @param[in]   Size      Bytes to allocate.
  @param[out]  Buffer    Receives the allocated pointer.

  @retval EFI_SUCCESS            Pool allocated.
  @retval EFI_INVALID_PARAMETER  Buffer is NULL.
  @retval EFI_OUT_OF_RESOURCES   malloc() failed.
**/
EFI_STATUS
EFIAPI
CoreAllocatePool (
  IN EFI_MEMORY_TYPE  PoolType,
  IN UINTN            Size,
  OUT VOID            **Buffer
  )
{
  if (Buffer == NULL) {
    return EFI_INVALID_PARAMETER;
  }

  //
  // UEFI Spec: Size=0 is valid — return a unique non-NULL pointer.
  //
  *Buffer = malloc ((Size == 0) ? 1 : Size);
  if (*Buffer == NULL) {
    return EFI_OUT_OF_RESOURCES;
  }
  return EFI_SUCCESS;
}

/**
  Free pool memory previously allocated by CoreAllocatePool.

  AUDIT: Passes through to libc free().  UEFI Spec says passing a
  NULL or already-freed pointer is undefined; we return
  EFI_INVALID_PARAMETER for NULL to help catch bugs during fuzzing.

  @param[in]  Buffer  Pointer returned by CoreAllocatePool.

  @retval EFI_SUCCESS            Memory freed.
  @retval EFI_INVALID_PARAMETER  Buffer is NULL.
**/
EFI_STATUS
EFIAPI
CoreFreePool (
  IN VOID  *Buffer
  )
{
  if (Buffer == NULL) {
    return EFI_INVALID_PARAMETER;
  }

  free (Buffer);
  return EFI_SUCCESS;
}

//
// ============================================================================
// ASSERT-crashing stubs for unimplemented Boot Services.
//
// AUDIT: Only 4 Boot Services still use these stubs:
//   - LoadImage   (requires PE/COFF loader — not needed for fuzzing)
//   - StartImage  (requires PE/COFF loader)
//   - Exit        (requires image tracking)
//   - UnloadImage (requires image tracking)
//
// All other Boot Services are fully implemented above.
// If a fuzz target calls one of these, the ASSERT will crash immediately,
// making the gap visible.  This is intentional — it's better to crash
// loudly than to silently return wrong data.
// ============================================================================
//

EFI_STATUS
EFIAPI
CoreEfiNotAvailableYetArg0 (
  VOID
  )
{
  ASSERT(FALSE);
  return EFI_UNSUPPORTED;
}

EFI_STATUS
EFIAPI
CoreEfiNotAvailableYetArg1 (
  UINTN Arg1
  )
{
  ASSERT(FALSE);
  return EFI_UNSUPPORTED;
}

EFI_STATUS
EFIAPI
CoreEfiNotAvailableYetArg2 (
  UINTN Arg1,
  UINTN Arg2
  )
{
  ASSERT(FALSE);
  return EFI_UNSUPPORTED;
}

EFI_STATUS
EFIAPI
CoreEfiNotAvailableYetArg3 (
  UINTN Arg1,
  UINTN Arg2,
  UINTN Arg3
  )
{
  ASSERT(FALSE);
  return EFI_UNSUPPORTED;
}

EFI_STATUS
EFIAPI
CoreEfiNotAvailableYetArg4 (
  UINTN Arg1,
  UINTN Arg2,
  UINTN Arg3,
  UINTN Arg4
  )
{
  ASSERT(FALSE);
  return EFI_UNSUPPORTED;
}

EFI_STATUS
EFIAPI
CoreEfiNotAvailableYetArg5 (
  UINTN Arg1,
  UINTN Arg2,
  UINTN Arg3,
  UINTN Arg4,
  UINTN Arg5
  )
{
  ASSERT(FALSE);
  return EFI_UNSUPPORTED;
}

EFI_STATUS
EFIAPI
CoreEfiNotAvailableYetArg6 (
  UINTN Arg1,
  UINTN Arg2,
  UINTN Arg3,
  UINTN Arg4,
  UINTN Arg5,
  UINTN Arg6
  )
{
  ASSERT(FALSE);
  return EFI_UNSUPPORTED;
}

/**
  Stall the CPU for a number of microseconds.

  In the host fuzzing environment, this is a no-op since we don't
  want fuzz iterations delayed by actual timing.

  @param  Microseconds  The number of microseconds to stall.

  @retval EFI_SUCCESS  Always succeeds.
**/
EFI_STATUS
EFIAPI
CoreStall (
  IN UINTN  Microseconds
  )
{
  return EFI_SUCCESS;
}

//
// ============================================================================
// Newly-implemented Boot Services (previously ASSERT-crashing stubs)
// ============================================================================
//

/**
  Set the system watchdog timer.

  In the host fuzzing environment, this is a no-op since there is no
  hardware watchdog.  Many UEFI drivers call
  gBS->SetWatchdogTimer(0, 0, 0, NULL) at startup to disable it.

  @param[in]  Timeout       Timeout in seconds (0 = disable).
  @param[in]  WatchdogCode  The numeric code logged on timeout.
  @param[in]  DataSize      Size of WatchdogData in bytes.
  @param[in]  WatchdogData  Optional null-terminated string logged on timeout.

  @retval EFI_SUCCESS  Always succeeds.
**/
EFI_STATUS
EFIAPI
CoreSetWatchdogTimer (
  IN UINTN   Timeout,
  IN UINT64  WatchdogCode,
  IN UINTN   DataSize,
  IN CHAR16  *WatchdogData  OPTIONAL
  )
{
  return EFI_SUCCESS;
}

//
// Monotonic counter — simple incrementing UINT64.
//
STATIC UINT64  mMonotonicCount = 0;

/**
  Return a monotonically increasing count.

  In real UEFI, the high 32 bits persist across reboots.  For host-based
  fuzzing we simply return a process-lifetime counter starting at 0.

  @param[out]  Count  Pointer to receive the next monotonic count.

  @retval EFI_SUCCESS            Count returned successfully.
  @retval EFI_INVALID_PARAMETER  Count is NULL.
**/
EFI_STATUS
EFIAPI
CoreGetNextMonotonicCount (
  OUT UINT64  *Count
  )
{
  if (Count == NULL) {
    return EFI_INVALID_PARAMETER;
  }

  *Count = mMonotonicCount++;
  return EFI_SUCCESS;
}

/**
  Compute the CRC32 of a data buffer.

  Wraps the BaseLib CalculateCrc32() function to match the Boot Service
  signature.  Used by FatPkg, ShellPkg, ACPI table drivers, etc.

  @param[in]   Data      Pointer to the data buffer.
  @param[in]   DataSize  Size of the data buffer in bytes.
  @param[out]  Crc32     Pointer to receive the CRC32 value.

  @retval EFI_SUCCESS            CRC32 computed successfully.
  @retval EFI_INVALID_PARAMETER  Data is NULL, DataSize is 0, or Crc32 is NULL.
**/
EFI_STATUS
EFIAPI
CoreCalculateCrc32 (
  IN  VOID    *Data,
  IN  UINTN   DataSize,
  OUT UINT32  *Crc32
  )
{
  if (Data == NULL || DataSize == 0 || Crc32 == NULL) {
    return EFI_INVALID_PARAMETER;
  }

  *Crc32 = CalculateCrc32 (Data, DataSize);
  return EFI_SUCCESS;
}

//
// ============================================================================
// Configuration Table
// ============================================================================
//

//
// Maximum number of configuration table entries.  64 is far more than any
// realistic UEFI system needs (typically < 10 entries).
//
#define MAX_CONFIG_TABLE_ENTRIES  64

STATIC EFI_CONFIGURATION_TABLE  mConfigTable[MAX_CONFIG_TABLE_ENTRIES];
STATIC UINTN                    mConfigTableCount = 0;

/**
  Install or update a configuration table entry in gST.

  If an entry with the matching VendorGuid already exists:
  - If Table is non-NULL, the existing entry is updated.
  - If Table is NULL, the existing entry is removed.
  If no matching entry exists and Table is non-NULL, a new entry is added.

  @param[in]  VendorGuid  GUID identifying the table.
  @param[in]  Table       Pointer to the table data, or NULL to remove.

  @retval EFI_SUCCESS            Table installed/updated/removed.
  @retval EFI_INVALID_PARAMETER  VendorGuid is NULL.
  @retval EFI_NOT_FOUND          Table is NULL and no matching entry exists.
  @retval EFI_OUT_OF_RESOURCES   Table is full.
**/
EFI_STATUS
EFIAPI
CoreInstallConfigurationTable (
  IN EFI_GUID  *VendorGuid,
  IN VOID      *Table
  )
{
  UINTN  Index;

  if (VendorGuid == NULL) {
    return EFI_INVALID_PARAMETER;
  }

  //
  // Search for an existing entry with this GUID
  //
  for (Index = 0; Index < mConfigTableCount; Index++) {
    if (CompareGuid (&mConfigTable[Index].VendorGuid, VendorGuid)) {
      if (Table != NULL) {
        //
        // Update existing entry
        //
        mConfigTable[Index].VendorTable = Table;
      } else {
        //
        // Remove: shift remaining entries down
        //
        mConfigTableCount--;
        CopyMem (
          &mConfigTable[Index],
          &mConfigTable[Index + 1],
          (mConfigTableCount - Index) * sizeof (EFI_CONFIGURATION_TABLE)
          );
        ZeroMem (&mConfigTable[mConfigTableCount], sizeof (EFI_CONFIGURATION_TABLE));
      }

      //
      // Update gST pointers
      //
      gST->NumberOfTableEntries = (UINT32)mConfigTableCount;
      gST->ConfigurationTable   = (mConfigTableCount > 0) ? mConfigTable : NULL;
      return EFI_SUCCESS;
    }
  }

  //
  // No existing entry found
  //
  if (Table == NULL) {
    return EFI_NOT_FOUND;
  }

  if (mConfigTableCount >= MAX_CONFIG_TABLE_ENTRIES) {
    return EFI_OUT_OF_RESOURCES;
  }

  //
  // Add new entry
  //
  CopyGuid (&mConfigTable[mConfigTableCount].VendorGuid, VendorGuid);
  mConfigTable[mConfigTableCount].VendorTable = Table;
  mConfigTableCount++;

  gST->NumberOfTableEntries = (UINT32)mConfigTableCount;
  gST->ConfigurationTable   = mConfigTable;

  return EFI_SUCCESS;
}

/**
  Return a minimal fake memory map.

  Real UEFI returns detailed memory region descriptors.  For host-based
  fuzzing a single EfiConventionalMemory region covering the whole 4 GB
  address space is sufficient to unblock any code that queries the map
  without providing hardware-accurate data.

  @param[in,out] MemoryMapSize      On input, buffer size in bytes.
                                     On output, required/actual size.
  @param[out]    MemoryMap           Buffer to receive the memory map.
  @param[out]    MapKey              Unique key for the current map.
  @param[out]    DescriptorSize      Size of each descriptor entry.
  @param[out]    DescriptorVersion   Descriptor format version.

  @retval EFI_SUCCESS           Map returned.
  @retval EFI_BUFFER_TOO_SMALL  Buffer too small; MemoryMapSize updated.
  @retval EFI_INVALID_PARAMETER MemoryMapSize is NULL.
**/
STATIC UINT64  mMemoryMapKey = 1;

EFI_STATUS
EFIAPI
CoreGetMemoryMap (
  IN OUT UINTN                  *MemoryMapSize,
  OUT    EFI_MEMORY_DESCRIPTOR  *MemoryMap,
  OUT    UINTN                  *MapKey,
  OUT    UINTN                  *DescriptorSize,
  OUT    UINT32                 *DescriptorVersion
  )
{
  UINTN  RequiredSize;

  if (MemoryMapSize == NULL) {
    return EFI_INVALID_PARAMETER;
  }

  RequiredSize = sizeof (EFI_MEMORY_DESCRIPTOR);

  if (*MemoryMapSize < RequiredSize) {
    *MemoryMapSize = RequiredSize;
    return EFI_BUFFER_TOO_SMALL;
  }

  if (MemoryMap == NULL) {
    return EFI_INVALID_PARAMETER;
  }

  //
  // Return a single descriptor covering 0 .. 4GB as conventional memory.
  //
  ZeroMem (MemoryMap, RequiredSize);
  MemoryMap->Type          = EfiConventionalMemory;
  MemoryMap->PhysicalStart = 0;
  MemoryMap->VirtualStart  = 0;
  MemoryMap->NumberOfPages = SIZE_4GB / EFI_PAGE_SIZE;
  MemoryMap->Attribute     = EFI_MEMORY_WB;

  *MemoryMapSize = RequiredSize;

  if (MapKey != NULL) {
    *MapKey = (UINTN)mMemoryMapKey;
  }

  if (DescriptorSize != NULL) {
    *DescriptorSize = sizeof (EFI_MEMORY_DESCRIPTOR);
  }

  if (DescriptorVersion != NULL) {
    *DescriptorVersion = EFI_MEMORY_DESCRIPTOR_VERSION;
  }

  return EFI_SUCCESS;
}

/**
  Terminate Boot Services.

  In the host fuzzing environment, this is a no-op.  No fuzz target
  should be calling ExitBootServices, but if one does, we return
  success instead of crashing.

  @param[in]  ImageHandle  Handle identifying the exiting image.
  @param[in]  MapKey       Key from the most recent GetMemoryMap call.

  @retval EFI_SUCCESS  Always succeeds.
**/
EFI_STATUS
EFIAPI
CoreExitBootServices (
  IN EFI_HANDLE  ImageHandle,
  IN UINTN       MapKey
  )
{
  return EFI_SUCCESS;
}

//
// ============================================================================
// ConOut no-op implementations (replace ASSERT-crashing stubs)
// ============================================================================
//

/**
  Reset the text output device.  No-op in host environment.

  @param[in]  This                 Protocol instance.
  @param[in]  ExtendedVerification Whether to perform extended verification.

  @retval EFI_SUCCESS  Always succeeds.
**/
STATIC
EFI_STATUS
EFIAPI
ConOutReset (
  IN EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL  *This,
  IN BOOLEAN                          ExtendedVerification
  )
{
  return EFI_SUCCESS;
}

/**
  Test if a string can be output.  Always returns success.

  @param[in]  This    Protocol instance.
  @param[in]  String  String to test.

  @retval EFI_SUCCESS  Always succeeds.
**/
STATIC
EFI_STATUS
EFIAPI
ConOutTestString (
  IN EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL  *This,
  IN CHAR16                           *String
  )
{
  return EFI_SUCCESS;
}

/**
  Query text output mode dimensions.

  Returns a fixed 80x25 for mode 0.

  @param[in]   This       Protocol instance.
  @param[in]   ModeNumber Mode to query.
  @param[out]  Columns    Number of columns.
  @param[out]  Rows       Number of rows.

  @retval EFI_SUCCESS       Mode info returned.
  @retval EFI_UNSUPPORTED   Mode number is not 0.
**/
STATIC
EFI_STATUS
EFIAPI
ConOutQueryMode (
  IN  EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL  *This,
  IN  UINTN                            ModeNumber,
  OUT UINTN                            *Columns,
  OUT UINTN                            *Rows
  )
{
  if (ModeNumber != 0) {
    return EFI_UNSUPPORTED;
  }

  if (Columns != NULL) {
    *Columns = 80;
  }

  if (Rows != NULL) {
    *Rows = 25;
  }

  return EFI_SUCCESS;
}

/**
  Set the text output mode.  No-op in host environment.

  @param[in]  This       Protocol instance.
  @param[in]  ModeNumber Mode to set.

  @retval EFI_SUCCESS  Always succeeds for mode 0.
**/
STATIC
EFI_STATUS
EFIAPI
ConOutSetMode (
  IN EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL  *This,
  IN UINTN                            ModeNumber
  )
{
  return (ModeNumber == 0) ? EFI_SUCCESS : EFI_UNSUPPORTED;
}

/**
  Set the foreground/background attribute.  No-op in host environment.

  @param[in]  This       Protocol instance.
  @param[in]  Attribute  Text attribute to set.

  @retval EFI_SUCCESS  Always succeeds.
**/
STATIC
EFI_STATUS
EFIAPI
ConOutSetAttribute (
  IN EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL  *This,
  IN UINTN                            Attribute
  )
{
  return EFI_SUCCESS;
}

/**
  Clear the screen.  No-op in host environment.

  @param[in]  This  Protocol instance.

  @retval EFI_SUCCESS  Always succeeds.
**/
STATIC
EFI_STATUS
EFIAPI
ConOutClearScreen (
  IN EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL  *This
  )
{
  return EFI_SUCCESS;
}

/**
  Set cursor position.  No-op in host environment.

  @param[in]  This    Protocol instance.
  @param[in]  Column  Column position.
  @param[in]  Row     Row position.

  @retval EFI_SUCCESS  Always succeeds.
**/
STATIC
EFI_STATUS
EFIAPI
ConOutSetCursorPosition (
  IN EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL  *This,
  IN UINTN                            Column,
  IN UINTN                            Row
  )
{
  return EFI_SUCCESS;
}

/**
  Enable or disable the cursor.  No-op in host environment.

  @param[in]  This     Protocol instance.
  @param[in]  Visible  TRUE to show cursor, FALSE to hide.

  @retval EFI_SUCCESS  Always succeeds.
**/
STATIC
EFI_STATUS
EFIAPI
ConOutEnableCursor (
  IN EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL  *This,
  IN BOOLEAN                          Visible
  )
{
  return EFI_SUCCESS;
}

EFI_BOOT_SERVICES mBootServices = {
  {
    EFI_BOOT_SERVICES_SIGNATURE,                                                          // Signature
    EFI_BOOT_SERVICES_REVISION,                                                           // Revision
    sizeof (EFI_BOOT_SERVICES),                                                           // HeaderSize
    0,                                                                                    // CRC32
    0                                                                                     // Reserved
  },
  (EFI_RAISE_TPL)                               CoreRaiseTpl,                             // RaiseTPL
  (EFI_RESTORE_TPL)                             CoreRestoreTpl,                           // RestoreTPL
  (EFI_ALLOCATE_PAGES)                          CoreAllocatePages,                        // AllocatePages
  (EFI_FREE_PAGES)                              CoreFreePages,                            // FreePages
  (EFI_GET_MEMORY_MAP)                          CoreGetMemoryMap,                         // GetMemoryMap
  (EFI_ALLOCATE_POOL)                           CoreAllocatePool,                         // AllocatePool
  (EFI_FREE_POOL)                               CoreFreePool,                             // FreePool
  (EFI_CREATE_EVENT)                            CoreCreateEvent,                          // CreateEvent
  (EFI_SET_TIMER)                               CoreSetTimer,                             // SetTimer
  (EFI_WAIT_FOR_EVENT)                          CoreWaitForEvent,                         // WaitForEvent
  (EFI_SIGNAL_EVENT)                            CoreSignalEvent,                          // SignalEvent
  (EFI_CLOSE_EVENT)                             CoreCloseEvent,                           // CloseEvent
  (EFI_CHECK_EVENT)                             CoreCheckEvent,                           // CheckEvent
  (EFI_INSTALL_PROTOCOL_INTERFACE)              CoreInstallProtocolInterface,             // InstallProtocolInterface
  (EFI_REINSTALL_PROTOCOL_INTERFACE)            CoreReinstallProtocolInterface,           // ReinstallProtocolInterface
  (EFI_UNINSTALL_PROTOCOL_INTERFACE)            CoreUninstallProtocolInterface,           // UninstallProtocolInterface
  (EFI_HANDLE_PROTOCOL)                         CoreHandleProtocol,                       // HandleProtocol
  (VOID *)                                      NULL,                                     // Reserved
  (EFI_REGISTER_PROTOCOL_NOTIFY)                CoreRegisterProtocolNotify,               // RegisterProtocolNotify
  (EFI_LOCATE_HANDLE)                           CoreLocateHandle,                         // LocateHandle
  (EFI_LOCATE_DEVICE_PATH)                      CoreLocateDevicePath,                     // LocateDevicePath
  (EFI_INSTALL_CONFIGURATION_TABLE)             CoreInstallConfigurationTable,            // InstallConfigurationTable
  (EFI_IMAGE_LOAD)                              CoreEfiNotAvailableYetArg6,               // LoadImage
  (EFI_IMAGE_START)                             CoreEfiNotAvailableYetArg3,               // StartImage
  (EFI_EXIT)                                    CoreEfiNotAvailableYetArg4,               // Exit
  (EFI_IMAGE_UNLOAD)                            CoreEfiNotAvailableYetArg1,               // UnloadImage
  (EFI_EXIT_BOOT_SERVICES)                      CoreExitBootServices,                     // ExitBootServices
  (EFI_GET_NEXT_MONOTONIC_COUNT)                CoreGetNextMonotonicCount,                // GetNextMonotonicCount
  (EFI_STALL)                                   CoreStall,                                // Stall
  (EFI_SET_WATCHDOG_TIMER)                      CoreSetWatchdogTimer,                     // SetWatchdogTimer
  (EFI_CONNECT_CONTROLLER)                      CoreConnectController,                    // ConnectController
  (EFI_DISCONNECT_CONTROLLER)                   CoreDisconnectController,                 // DisconnectController
  (EFI_OPEN_PROTOCOL)                           CoreOpenProtocol,                         // OpenProtocol
  (EFI_CLOSE_PROTOCOL)                          CoreCloseProtocol,                        // CloseProtocol
  (EFI_OPEN_PROTOCOL_INFORMATION)               CoreOpenProtocolInformation,              // OpenProtocolInformation
  (EFI_PROTOCOLS_PER_HANDLE)                    CoreProtocolsPerHandle,                   // ProtocolsPerHandle
  (EFI_LOCATE_HANDLE_BUFFER)                    CoreLocateHandleBuffer,                   // LocateHandleBuffer
  (EFI_LOCATE_PROTOCOL)                         CoreLocateProtocol,                       // LocateProtocol
  (EFI_INSTALL_MULTIPLE_PROTOCOL_INTERFACES)    CoreInstallMultipleProtocolInterfaces,    // InstallMultipleProtocolInterfaces
  (EFI_UNINSTALL_MULTIPLE_PROTOCOL_INTERFACES)  CoreUninstallMultipleProtocolInterfaces,  // UninstallMultipleProtocolInterfaces
  (EFI_CALCULATE_CRC32)                         CoreCalculateCrc32,                       // CalculateCrc32
  (EFI_COPY_MEM)                                CopyMem,                                  // CopyMem
  (EFI_SET_MEM)                                 SetMem,                                   // SetMem
  (EFI_CREATE_EVENT_EX)                         CoreCreateEventEx                         // CreateEventEx
};

EFI_STATUS
EFIAPI
OutputString (
  IN EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL        *This,
  IN CHAR16                                 *String
  )
{
  DEBUG ((DEBUG_INFO, "%s", String));
  return EFI_SUCCESS;
}

EFI_SIMPLE_TEXT_OUTPUT_MODE mMode = {
  1, // MaxMode
  0, // Mode
  0, // Attribute
  80, // CursorColumn
  25, // CursorRow
  FALSE, // CursorVisible
};

EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL mConOut = {
  (EFI_TEXT_RESET)               ConOutReset,              // Reset
  OutputString,
  (EFI_TEXT_TEST_STRING)         ConOutTestString,          // TestString
  (EFI_TEXT_QUERY_MODE)          ConOutQueryMode,           // QueryMode
  (EFI_TEXT_SET_MODE)            ConOutSetMode,             // SetMode
  (EFI_TEXT_SET_ATTRIBUTE)       ConOutSetAttribute,        // SetAttribute
  (EFI_TEXT_CLEAR_SCREEN)        ConOutClearScreen,         // ClearScreen
  (EFI_TEXT_SET_CURSOR_POSITION) ConOutSetCursorPosition,   // SetCursorPosition
  (EFI_TEXT_ENABLE_CURSOR)       ConOutEnableCursor,        // EnableCursor
  &mMode,                                                  // Mode
};

EFI_SYSTEM_TABLE mEfiSystemTableTemplate = {
  {
    EFI_SYSTEM_TABLE_SIGNATURE,                                           // Signature
    EFI_SYSTEM_TABLE_REVISION,                                            // Revision
    sizeof (EFI_SYSTEM_TABLE),                                            // HeaderSize
    0,                                                                    // CRC32
    0                                                                     // Reserved
  },
  NULL,                                                                   // FirmwareVendor
  0,                                                                      // FirmwareRevision
  NULL,                                                                   // ConsoleInHandle
  NULL,                                                                   // ConIn
  NULL,                                                                   // ConsoleOutHandle
  &mConOut,                                                               // ConOut
  NULL,                                                                   // StandardErrorHandle
  NULL,                                                                   // StdErr
  NULL,                                                                   // RuntimeServices
  &mBootServices,                                                         // BootServices
  0,                                                                      // NumberOfConfigurationTableEntries
  NULL                                                                    // ConfigurationTable
};

EFI_STATUS
EFIAPI
UefiBootServicesTableLibConstructor (
  VOID
  )
{
  EFI_STATUS  Status;

  //
  // Install LoadedImageProtocol on gImageHandle (creates the handle)
  //
  Status = gBS->InstallProtocolInterface (
                  &gImageHandle,
                  &gEfiLoadedImageProtocolGuid,
                  EFI_NATIVE_INTERFACE,
                  NULL
                  );
  if (EFI_ERROR (Status)) {
    return Status;
  }

  //
  // Set gDxeCoreImageHandle so CoreHandleProtocol/CoreOpenProtocol
  // have a valid ImageHandle for OPEN_PROTOCOL_DATA tracking
  //
  gDxeCoreImageHandle = gImageHandle;

  //
  // Create gFuzzHandle - the single shared handle where all mock
  // protocols will be installed by mock library constructors.
  // Install a dummy LoadedImageProtocol to seed the handle.
  //
  Status = gBS->InstallProtocolInterface (
                  &gFuzzHandle,
                  &gEfiLoadedImageProtocolGuid,
                  EFI_NATIVE_INTERFACE,
                  NULL
                  );
  if (EFI_ERROR (Status)) {
    return Status;
  }

  //
  // Wire gST->RuntimeServices to gRT if the Runtime Services library
  // has been linked.  The weak attribute means the linker resolves to
  // NULL when UefiRuntimeServicesTableLibHost is not linked, avoiding
  // undefined-reference errors in test binaries that don't need RT.
  //
  {
    extern EFI_RUNTIME_SERVICES  *gRT __attribute__((weak));
    if (&gRT != NULL && gRT != NULL) {
      gST->RuntimeServices = gRT;
    }
  }

  return Status;
}
