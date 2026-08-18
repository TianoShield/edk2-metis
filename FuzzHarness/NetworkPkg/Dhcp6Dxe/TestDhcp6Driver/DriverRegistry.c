/** @file DriverRegistry.c
    Driver registry for Dhcp6Dxe harness.

    Single-driver registry for L1 harness.  Add more entries to build
    deeper harness levels (L1L2, L3, ...) without changing harness code.

    Copyright (c) 2025-2026 TianoShield Contributors.
    SPDX-License-Identifier: BSD-2-Clause-Patent
**/

#include <Library/HostDispatcherLib.h>

extern EFI_STATUS EFIAPI Dhcp6DriverEntryPoint (EFI_HANDLE ImageHandle, EFI_SYSTEM_TABLE *SystemTable);

HOST_DRIVER_ENTRY gHostDriverRegistry[] = {
  { L"Dhcp6Dxe", Dhcp6DriverEntryPoint, NULL, FALSE },
  HOST_DRIVER_ENTRY_END
};
