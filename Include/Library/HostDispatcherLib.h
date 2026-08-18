/** @file HostDispatcherLib.h
    DXE-Dispatcher-style driver initialization for host fuzzing.

    This library provides a mini-dispatcher that emulates the UEFI DXE Core's
    driver connection mechanism.  Instead of manually calling EntryPoint →
    Supported → Start for each driver in dependency order, harnesses declare
    a driver registry and call HostDispatchDrivers() which:

    1. Calls each driver's EntryPoint (installs DriverBinding on ImageHandle)
    2. Calls gBS->ConnectController() which iterates all DriverBindings,
       calling Supported() then Start() on matching controllers

    This leverages the existing CoreConnectSingleController implementation
    in UefiBootServicesTableLibHost which handles:
    - Driver priority sorting by Version field
    - Retry loop until no more drivers can start
    - Platform/Bus override protocol support

    Usage:
    ======
    1. Create a driver registry (manually or via gen_driver_registry.py):

       extern EFI_STATUS EFIAPI Ip4DriverEntryPoint(EFI_HANDLE, EFI_SYSTEM_TABLE*);
       extern EFI_STATUS EFIAPI Udp4DriverEntryPoint(EFI_HANDLE, EFI_SYSTEM_TABLE*);
       extern EFI_STATUS EFIAPI Dhcp4DriverEntryPoint(EFI_HANDLE, EFI_SYSTEM_TABLE*);

       HOST_DRIVER_ENTRY gDriverRegistry[] = {
         { L"Ip4Dxe",   Ip4DriverEntryPoint,   NULL, FALSE },
         { L"Udp4Dxe",  Udp4DriverEntryPoint,  NULL, FALSE },
         { L"Dhcp4Dxe", Dhcp4DriverEntryPoint, NULL, FALSE },
         HOST_DRIVER_ENTRY_END
       };

    2. In InitializeHarness():

       Status = HostDispatchDrivers(gFuzzHandle, gDriverRegistry);
       // Then get ServiceBinding + CreateChild for top-layer protocol

    3. In FuzzDriverStopRestart():

       HostDisconnectDrivers(gFuzzHandle, gDriverRegistry);
       HostReconnectDrivers(gFuzzHandle, gDriverRegistry);

    Copyright (c) 2025-2026 TianoShield Contributors.
    SPDX-License-Identifier: BSD-2-Clause-Patent
**/

#ifndef __HOST_DISPATCHER_LIB_H__
#define __HOST_DISPATCHER_LIB_H__

#include <Uefi.h>

//
// Driver entry point function signature (same as EFI_IMAGE_ENTRY_POINT)
//
typedef
EFI_STATUS
(EFIAPI *HOST_DRIVER_ENTRY_POINT)(
  IN EFI_HANDLE        ImageHandle,
  IN EFI_SYSTEM_TABLE  *SystemTable
  );

//
// Driver registry entry — describes one driver to be dispatched
//
typedef struct {
  CONST CHAR16              *Name;         ///< Driver name for debug output
  HOST_DRIVER_ENTRY_POINT   EntryPoint;    ///< XxxDriverEntryPoint function
  EFI_HANDLE                ImageHandle;   ///< Allocated at dispatch time (OUT)
  BOOLEAN                   Started;       ///< TRUE after successful Start (OUT)
} HOST_DRIVER_ENTRY;

//
// Sentinel value for end of registry array
//
#define HOST_DRIVER_ENTRY_END  { NULL, NULL, NULL, FALSE }

/**
  Dispatch all drivers in the registry to the specified controller.

  Phase 1: For each driver in Registry order:
    - Allocate a fresh ImageHandle via InstallMultipleProtocolInterfaces
    - Call EntryPoint(ImageHandle, gST) — this installs DriverBinding

  Phase 2: Call gBS->ConnectController(ControllerHandle, NULL, NULL, FALSE)
    - CoreConnectSingleController iterates all DriverBindings
    - For each, calls Supported() then Start() if supported
    - Repeats until no more drivers can start

  The registry order should be topologically sorted by dependencies
  (drivers that PRODUCE protocols needed by later drivers come first).
  However, ConnectController's retry loop handles most ordering issues.

  @param[in]      ControllerHandle  Handle to connect drivers to (e.g., gFuzzHandle)
  @param[in,out]  Registry          NULL-terminated array of driver entries.
                                    ImageHandle and Started fields are updated.

  @retval EFI_SUCCESS           At least one driver started successfully.
  @retval EFI_NOT_FOUND         No drivers could start on ControllerHandle.
  @retval EFI_INVALID_PARAMETER ControllerHandle is NULL or Registry is NULL.
**/
EFI_STATUS
EFIAPI
HostDispatchDrivers (
  IN     EFI_HANDLE        ControllerHandle,
  IN OUT HOST_DRIVER_ENTRY *Registry
  );

/**
  Disconnect all drivers from the controller (reverse order).

  For each driver in reverse Registry order:
    - If Started is TRUE, calls gBS->DisconnectController

  This properly tears down the driver stack in dependency order.

  @param[in]      ControllerHandle  Handle to disconnect drivers from.
  @param[in,out]  Registry          Driver registry (Started flags are cleared).

  @retval EFI_SUCCESS           All drivers disconnected.
  @retval EFI_INVALID_PARAMETER ControllerHandle is NULL or Registry is NULL.
**/
EFI_STATUS
EFIAPI
HostDisconnectDrivers (
  IN     EFI_HANDLE        ControllerHandle,
  IN OUT HOST_DRIVER_ENTRY *Registry
  );

/**
  Reconnect all drivers to the controller.

  Equivalent to HostDisconnectDrivers() followed by ConnectController().
  Does NOT re-call EntryPoints — DriverBindings persist from initial dispatch.

  @param[in]      ControllerHandle  Handle to reconnect drivers to.
  @param[in,out]  Registry          Driver registry.

  @retval EFI_SUCCESS           At least one driver restarted successfully.
  @retval EFI_NOT_FOUND         No drivers could restart.
  @retval EFI_INVALID_PARAMETER ControllerHandle is NULL or Registry is NULL.
**/
EFI_STATUS
EFIAPI
HostReconnectDrivers (
  IN     EFI_HANDLE        ControllerHandle,
  IN OUT HOST_DRIVER_ENTRY *Registry
  );

/**
  Get the count of drivers in a registry.

  @param[in]  Registry  NULL-terminated driver registry.

  @return  Number of driver entries (not counting the sentinel).
**/
UINTN
EFIAPI
HostGetDriverCount (
  IN CONST HOST_DRIVER_ENTRY *Registry
  );

#endif // __HOST_DISPATCHER_LIB_H__
