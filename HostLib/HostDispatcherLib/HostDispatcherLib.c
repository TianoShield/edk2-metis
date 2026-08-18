/** @file HostDispatcherLib.c
    DXE-Dispatcher-style driver initialization for host fuzzing.

    Implements the mini-dispatcher that emulates UEFI DXE Core's driver
    connection mechanism.  See HostDispatcherLib.h for full documentation.

    Key Design:
    ===========
    1. Each driver gets its own ImageHandle — this is critical because
       UEFI DriverBinding installation requires a unique ImageHandle per
       driver.  Using the same handle for multiple drivers causes
       InstallMultipleProtocolInterfaces to fail with INVALID_PARAMETER.

    2. We leverage the existing CoreConnectSingleController implementation
       in UefiBootServicesTableLibHost rather than reimplementing the
       Supported/Start iteration.  This ensures we get the same behavior
       as real UEFI including Version-based priority sorting.

    3. The registry order matters for EntryPoint calls (which install
       DriverBindings), but ConnectController's retry loop handles most
       dependency ordering for Supported/Start.

    Copyright (c) 2025-2026 TianoShield Contributors.
    SPDX-License-Identifier: BSD-2-Clause-Patent
**/

#include <Uefi.h>
#include <Library/BaseLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/DebugLib.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Library/HostDispatcherLib.h>

/**
  Get the count of drivers in a registry.

  @param[in]  Registry  NULL-terminated driver registry.

  @return  Number of driver entries (not counting the sentinel).
**/
UINTN
EFIAPI
HostGetDriverCount (
  IN CONST HOST_DRIVER_ENTRY *Registry
  )
{
  UINTN  Count;

  if (Registry == NULL) {
    return 0;
  }

  for (Count = 0; Registry[Count].EntryPoint != NULL; Count++) {
    // Count entries until sentinel
  }

  return Count;
}

/**
  Dispatch all drivers in the registry to the specified controller.

  Phase 1: For each driver in Registry order:
    - Allocate a fresh ImageHandle via InstallMultipleProtocolInterfaces
    - Call EntryPoint(ImageHandle, gST) — this installs DriverBinding

  Phase 2: Call gBS->ConnectController(ControllerHandle, NULL, NULL, FALSE)
    - CoreConnectSingleController iterates all DriverBindings
    - For each, calls Supported() then Start() if supported
    - Repeats until no more drivers can start

  @param[in]      ControllerHandle  Handle to connect drivers to (e.g., gFuzzHandle)
  @param[in,out]  Registry          NULL-terminated array of driver entries.

  @retval EFI_SUCCESS           At least one driver started successfully.
  @retval EFI_NOT_FOUND         No drivers could start on ControllerHandle.
  @retval EFI_INVALID_PARAMETER ControllerHandle is NULL or Registry is NULL.
**/
EFI_STATUS
EFIAPI
HostDispatchDrivers (
  IN     EFI_HANDLE        ControllerHandle,
  IN OUT HOST_DRIVER_ENTRY *Registry
  )
{
  EFI_STATUS  Status;
  EFI_STATUS  ConnectStatus;
  UINTN       Index;
  UINTN       DriverCount;
  UINTN       EntryPointSuccessCount;

  DEBUG ((DEBUG_INFO, "HostDispatcher: DispatchDrivers starting\n"));

  if (ControllerHandle == NULL) {
    DEBUG ((DEBUG_ERROR, "HostDispatcher: ControllerHandle is NULL\n"));
    return EFI_INVALID_PARAMETER;
  }

  if (Registry == NULL) {
    DEBUG ((DEBUG_ERROR, "HostDispatcher: Registry is NULL\n"));
    return EFI_INVALID_PARAMETER;
  }

  DriverCount = HostGetDriverCount (Registry);
  if (DriverCount == 0) {
    DEBUG ((DEBUG_WARN, "HostDispatcher: Registry is empty\n"));
    return EFI_NOT_FOUND;
  }

  DEBUG ((DEBUG_INFO, "HostDispatcher: %d drivers in registry\n", DriverCount));

  //
  // Phase 1: Call all EntryPoints to install DriverBinding protocols
  //
  // Each driver needs its own ImageHandle.  We allocate a fresh handle
  // by calling InstallMultipleProtocolInterfaces with no protocols —
  // this creates a valid handle that the driver can use.
  //
  EntryPointSuccessCount = 0;

  for (Index = 0; Index < DriverCount; Index++) {
    //
    // Allocate a fresh ImageHandle for this driver
    //
    Registry[Index].ImageHandle = NULL;
    Status = gBS->InstallMultipleProtocolInterfaces (
                    &Registry[Index].ImageHandle,
                    NULL
                    );
    if (EFI_ERROR (Status)) {
      DEBUG ((DEBUG_ERROR, "HostDispatcher: [%s] Failed to allocate ImageHandle: %r\n",
              Registry[Index].Name, Status));
      continue;
    }

    //
    // Call the driver's EntryPoint
    // This typically calls EfiLibInstallDriverBindingComponentName2() which
    // installs EFI_DRIVER_BINDING_PROTOCOL on the ImageHandle.
    //
    DEBUG ((DEBUG_INFO, "HostDispatcher: [%s] Calling EntryPoint (ImageHandle=%p)\n",
            Registry[Index].Name, Registry[Index].ImageHandle));

    Status = Registry[Index].EntryPoint (Registry[Index].ImageHandle, gST);

    DEBUG ((DEBUG_INFO, "HostDispatcher: [%s] EntryPoint returned %r\n",
            Registry[Index].Name, Status));

    if (!EFI_ERROR (Status)) {
      EntryPointSuccessCount++;
    }
  }

  if (EntryPointSuccessCount == 0) {
    DEBUG ((DEBUG_ERROR, "HostDispatcher: All EntryPoints failed\n"));
    return EFI_DEVICE_ERROR;
  }

  DEBUG ((DEBUG_INFO, "HostDispatcher: %d/%d EntryPoints succeeded\n",
          EntryPointSuccessCount, DriverCount));

  //
  // Phase 2: Let ConnectController do the Supported/Start iteration
  //
  // CoreConnectSingleController (in UefiBootServicesTableLibHost/DriverSupport.c):
  // 1. Locates all EFI_DRIVER_BINDING_PROTOCOL instances
  // 2. Sorts them by Version (highest first)
  // 3. For each, calls Supported(ControllerHandle) then Start(ControllerHandle)
  // 4. Repeats until no more drivers can start
  //
  // We use Recursive=FALSE because we only want to connect to ControllerHandle,
  // not recursively to any child handles that might be created.
  //
  DEBUG ((DEBUG_INFO, "HostDispatcher: Calling ConnectController on %p\n", ControllerHandle));

  ConnectStatus = gBS->ConnectController (
                         ControllerHandle,
                         NULL,   // No specific driver image handles
                         NULL,   // No remaining device path
                         FALSE   // Not recursive
                         );

  DEBUG ((DEBUG_INFO, "HostDispatcher: ConnectController returned %r\n", ConnectStatus));

  //
  // Mark drivers as started based on whether their DriverBinding is now

  // managing the controller.  We check this by seeing if the driver's
  // DriverBinding.Start() was called (indicated by protocols being installed).
  //
  // For simplicity, we mark all drivers as "started" if ConnectController
  // succeeded.  A more precise implementation would check each driver's
  // DriverBinding to see if it's actually managing the controller.
  //
  if (!EFI_ERROR (ConnectStatus)) {
    for (Index = 0; Index < DriverCount; Index++) {
      Registry[Index].Started = TRUE;
    }
  }

  return ConnectStatus;
}

/**
  Disconnect all drivers from the controller (reverse order).

  For each driver in reverse Registry order:
    - Calls gBS->DisconnectController to stop the driver

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
  )
{
  EFI_STATUS  Status;
  UINTN       DriverCount;
  INTN        Index;

  DEBUG ((DEBUG_INFO, "HostDispatcher: DisconnectDrivers starting\n"));

  if (ControllerHandle == NULL || Registry == NULL) {
    return EFI_INVALID_PARAMETER;
  }

  DriverCount = HostGetDriverCount (Registry);
  if (DriverCount == 0) {
    return EFI_SUCCESS;
  }

  //
  // Disconnect in reverse order (top-layer drivers first)
  //
  // DisconnectController with DriverImageHandle=NULL and ChildHandle=NULL
  // disconnects ALL drivers from the controller.  However, we call it
  // once per driver to give each a chance to clean up properly.
  //
  // Actually, the cleanest approach is to call DisconnectController once
  // with NULL parameters — it will iterate through all drivers and call
  // their Stop() functions in the correct order.
  //
  DEBUG ((DEBUG_INFO, "HostDispatcher: Calling DisconnectController on %p\n", ControllerHandle));

  Status = gBS->DisconnectController (
                  ControllerHandle,
                  NULL,   // Disconnect all drivers
                  NULL    // Disconnect all children
                  );

  DEBUG ((DEBUG_INFO, "HostDispatcher: DisconnectController returned %r\n", Status));

  //
  // Clear Started flags
  //
  for (Index = (INTN)DriverCount - 1; Index >= 0; Index--) {
    Registry[Index].Started = FALSE;
  }

  return EFI_SUCCESS;
}

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
  )
{
  EFI_STATUS  Status;
  UINTN       Index;
  UINTN       DriverCount;

  DEBUG ((DEBUG_INFO, "HostDispatcher: ReconnectDrivers starting\n"));

  if (ControllerHandle == NULL || Registry == NULL) {
    return EFI_INVALID_PARAMETER;
  }

  //
  // Phase 1: Disconnect all drivers
  //
  Status = HostDisconnectDrivers (ControllerHandle, Registry);
  DEBUG ((DEBUG_INFO, "HostDispatcher: Disconnect phase returned %r\n", Status));

  //
  // Phase 2: Reconnect via ConnectController
  //
  // We do NOT re-call EntryPoints because the DriverBinding protocols
  // are still installed on the ImageHandles from the initial dispatch.
  // ConnectController will find them and call Supported/Start again.
  //
  DEBUG ((DEBUG_INFO, "HostDispatcher: Calling ConnectController for reconnect\n"));

  Status = gBS->ConnectController (
                  ControllerHandle,
                  NULL,
                  NULL,
                  FALSE
                  );

  DEBUG ((DEBUG_INFO, "HostDispatcher: Reconnect ConnectController returned %r\n", Status));

  //
  // Update Started flags
  //
  if (!EFI_ERROR (Status)) {
    DriverCount = HostGetDriverCount (Registry);
    for (Index = 0; Index < DriverCount; Index++) {
      Registry[Index].Started = TRUE;
    }
  }

  return Status;
}
