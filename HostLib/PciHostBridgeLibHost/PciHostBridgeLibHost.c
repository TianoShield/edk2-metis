/** @file PciHostBridgeLibHost.c
    Host-compatible PciHostBridgeLib — returns a single PCI root bridge
    with simple apertures suitable for host-based fuzz testing.

    Copyright (c) 2026, HBFAplus Contributors. All rights reserved.
    SPDX-License-Identifier: BSD-2-Clause-Patent
**/

#include <PiDxe.h>
#include <IndustryStandard/Pci.h>
#include <Protocol/PciHostBridgeResourceAllocation.h>
#include <Library/BaseMemoryLib.h>
#include <Library/DebugLib.h>
#include <Library/DevicePathLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/PciHostBridgeLib.h>

#pragma pack(1)
typedef struct {
  ACPI_HID_DEVICE_PATH      AcpiDevicePath;
  EFI_DEVICE_PATH_PROTOCOL  EndDevicePath;
} HOST_PCI_ROOT_BRIDGE_DEVICE_PATH;
#pragma pack()

STATIC HOST_PCI_ROOT_BRIDGE_DEVICE_PATH  mRootBridgeDevicePath = {
  {
    {
      ACPI_DEVICE_PATH,
      ACPI_DP,
      {
        (UINT8)(sizeof (ACPI_HID_DEVICE_PATH)),
        (UINT8)((sizeof (ACPI_HID_DEVICE_PATH)) >> 8)
      }
    },
    EISA_PNP_ID (0x0A03),  // PCI root bridge
    0                       // UID
  },
  {
    END_DEVICE_PATH_TYPE,
    END_ENTIRE_DEVICE_PATH_SUBTYPE,
    {
      END_DEVICE_PATH_LENGTH,
      0
    }
  }
};

//
// Single root bridge: Bus 0-0xFF, IO 0x1000-0xFFFF, Mem 0x80000000-0xFBFFFFFF
//
STATIC PCI_ROOT_BRIDGE  mRootBridge = {
  0,                                            // Segment
  EFI_PCI_ATTRIBUTE_ISA_MOTHERBOARD_IO |
    EFI_PCI_ATTRIBUTE_ISA_IO |
    EFI_PCI_ATTRIBUTE_VGA_MEMORY |
    EFI_PCI_ATTRIBUTE_VGA_IO_16 |
    EFI_PCI_ATTRIBUTE_VGA_PALETTE_IO_16,        // Supports
  0,                                            // Attributes
  FALSE,                                        // DmaAbove4G
  FALSE,                                        // NoExtendedConfigSpace
  TRUE,                                         // ResourceAssigned
  EFI_PCI_HOST_BRIDGE_COMBINE_MEM_PMEM,        // AllocationAttributes
  { 0,          0xFF,        0 },               // Bus
  { 0x1000,     0xFFFF,      0 },               // Io
  { 0x80000000, 0xFBFFFFFF,  0 },               // Mem
  { MAX_UINT64, 0,           0 },               // PMem      (disabled)
  { MAX_UINT64, 0,           0 },               // MemAbove4G(disabled)
  { MAX_UINT64, 0,           0 },               // PMemAbove4G(disabled)
  NULL                                          // DevicePath (set below)
};

/**
  Return the root bridges for this platform.

  @param[out] Count  Number of root bridges returned.

  @return  Heap-allocated array of PCI_ROOT_BRIDGE.  Caller frees via
           PciHostBridgeFreeRootBridges().
**/
PCI_ROOT_BRIDGE *
EFIAPI
PciHostBridgeGetRootBridges (
  OUT UINTN  *Count
  )
{
  PCI_ROOT_BRIDGE  *Bridge;

  *Count = 1;
  Bridge = AllocateCopyPool (sizeof (mRootBridge), &mRootBridge);
  if (Bridge == NULL) {
    *Count = 0;
    return NULL;
  }

  Bridge->DevicePath = (EFI_DEVICE_PATH_PROTOCOL *)&mRootBridgeDevicePath;
  return Bridge;
}

/**
  Free root bridges returned by PciHostBridgeGetRootBridges().
**/
VOID
EFIAPI
PciHostBridgeFreeRootBridges (
  IN PCI_ROOT_BRIDGE  *Bridges,
  IN UINTN            Count
  )
{
  if (Bridges != NULL) {
    FreePool (Bridges);
  }
}

/**
  Inform the platform that a resource conflict has happened.
**/
VOID
EFIAPI
PciHostBridgeResourceConflict (
  IN EFI_HANDLE  HostBridgeHandle,
  IN VOID        *Configuration
  )
{
  DEBUG ((DEBUG_WARN, "[PciHostBridgeLibHost] ResourceConflict (no-op)\n"));
}
