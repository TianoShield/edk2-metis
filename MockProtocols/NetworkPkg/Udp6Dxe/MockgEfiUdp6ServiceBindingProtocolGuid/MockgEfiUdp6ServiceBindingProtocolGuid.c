/** @file MockgEfiUdp6ServiceBindingProtocolGuid.c
    HBFAplus Mock UDP6 Service Binding Protocol Implementation.

    Mock EFI_SERVICE_BINDING_PROTOCOL for gEfiUdp6ServiceBindingProtocolGuid.

    Behaviour:
      - CreateChild:  sets *ChildHandle = gFuzzHandle, returns SUCCESS.
                      The mock EFI_UDP6_PROTOCOL is already installed on gFuzzHandle
                      by MockgEfiUdp6ProtocolGuid, so the caller can immediately
                      OpenProtocol the child and get a working UDP6 instance.
      - DestroyChild: no-op, returns SUCCESS.

    Why single-handle?
      Real UEFI drivers call ServiceBinding->CreateChild() to get a child handle,
      then OpenProtocol(ChildHandle, gEfiUdp6ProtocolGuid) to get the protocol.
      In the fuzzing environment we skip the child-handle hierarchy and point
      everything at gFuzzHandle where the mock UDP6 is installed.

    Copyright (c) 2025, HBFAplus Contributors. All rights reserved.
    SPDX-License-Identifier: BSD-2-Clause-Patent
**/

//=============================================================================
// UEFI Spec Audit — §29.2 (EFI UDP6 Service Binding Protocol)
//
// Real UEFI: Service Binding provides CreateChild/DestroyChild to
//            manage per-flow UDP6 child driver instances.
// Our mock:  CreateChild returns gFuzzHandle; DestroyChild is a no-op.
// Deviations: None — minimal stub matching spec interface.
//=============================================================================

#include <Uefi.h>
#include <Library/BaseLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/DebugLib.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Library/FuzzContextLib.h>
#include <Protocol/ServiceBinding.h>
#include <Protocol/Udp6.h>
//=============================================================================
// Module-scope state
//=============================================================================

STATIC EFI_SERVICE_BINDING_PROTOCOL  mMockUdp6ServiceBinding;
STATIC UINT32                        mCreateChildCount  = 0;
STATIC UINT32                        mDestroyChildCount = 0;

extern EFI_HANDLE gFuzzHandle;

//=============================================================================
// Mock Service Binding function implementations
//=============================================================================

/**
  Mock CreateChild — returns gFuzzHandle as the child.

  Real flow (Udp6Dxe):
    1. Allocates a UDP_IO_PORT structure
    2. Creates a new handle, installs EFI_UDP6_PROTOCOL on it
    3. Returns the new handle in *ChildHandle

  Mock flow (single-handle model):
    1. Sets *ChildHandle = gFuzzHandle
    2. The existing mock EFI_UDP6_PROTOCOL is already on gFuzzHandle

  @param[in]      This         Pointer to the ServiceBinding protocol instance.
  @param[in,out]  ChildHandle  Pointer to receive the child handle.

  @retval EFI_SUCCESS           Child handle returned.
  @retval EFI_INVALID_PARAMETER ChildHandle is NULL.
**/
STATIC
EFI_STATUS
EFIAPI
MockUdp6SbCreateChild (
  IN     EFI_SERVICE_BINDING_PROTOCOL  *This,
  IN OUT EFI_HANDLE                    *ChildHandle
  )
{
  if (ChildHandle == NULL) {
    return EFI_INVALID_PARAMETER;
  }

  DEBUG ((DEBUG_INFO, "MockUdp6SB: CreateChild → gFuzzHandle\n"));

  //
  // Single-handle model: all mock protocols live on gFuzzHandle.
  // The caller will OpenProtocol(gFuzzHandle, &gEfiUdp6ProtocolGuid, ...)
  // and get the mock UDP6 protocol already installed there.
  //
  *ChildHandle = gFuzzHandle;
  mCreateChildCount++;

  return EFI_SUCCESS;
}

/**
  Mock DestroyChild — no-op.

  In real UEFI this would tear down the child handle and free resources.
  For fuzzing we don't need to do anything.

  @param[in]  This         Pointer to the ServiceBinding protocol instance.
  @param[in]  ChildHandle  The child handle to destroy.

  @retval EFI_SUCCESS  Always succeeds.
**/
STATIC
EFI_STATUS
EFIAPI
MockUdp6SbDestroyChild (
  IN EFI_SERVICE_BINDING_PROTOCOL  *This,
  IN EFI_HANDLE                    ChildHandle
  )
{
  DEBUG ((DEBUG_INFO, "MockUdp6SB: DestroyChild (handle=%p)\n", ChildHandle));
  mDestroyChildCount++;
  return EFI_SUCCESS;
}

//=============================================================================
// State Reset
//=============================================================================

STATIC
VOID
EFIAPI
ResetState (
  VOID
  )
{
  mCreateChildCount  = 0;
  mDestroyChildCount = 0;
}

//=============================================================================
// Counter Accessors (test-only, accessed via extern)
//=============================================================================

UINT32
EFIAPI
MockUdp6ServiceBindingGetCreateCount (
  VOID
  )
{
  return mCreateChildCount;
}

UINT32
EFIAPI
MockUdp6ServiceBindingGetDestroyCount (
  VOID
  )
{
  return mDestroyChildCount;
}

//=============================================================================
// Library Constructor
//=============================================================================

/**
  Initialize mock UDP6 Service Binding protocol and install on gFuzzHandle.

  This must run BEFORE MockgEfiUdp6ProtocolGuid constructor (or order
  doesn't matter since they install different GUIDs on the same handle).

  @retval RETURN_SUCCESS  Always succeeds.
**/
RETURN_STATUS
EFIAPI
MockgEfiUdp6ServiceBindingProtocolGuidConstructor (
  VOID
  )
{
  EFI_STATUS  Status;

  DEBUG ((DEBUG_INFO, "MockgEfiUdp6ServiceBindingProtocolGuid: Constructor\n"));

  //
  // Wire up the two Service Binding function pointers
  //
  mMockUdp6ServiceBinding.CreateChild  = MockUdp6SbCreateChild;
  mMockUdp6ServiceBinding.DestroyChild = MockUdp6SbDestroyChild;

  //
  // Reset counters and register with reset registry
  //
  ResetState ();
  MockProtocolRegisterReset (ResetState);

  if ((gBS == NULL) || (gFuzzHandle == NULL)) {
    DEBUG ((DEBUG_WARN, "MockgEfiUdp6ServiceBindingProtocolGuid: gBS or gFuzzHandle NULL — skipping install\n"));
    return RETURN_SUCCESS;
  }

  Status = gBS->InstallProtocolInterface (
                  &gFuzzHandle,
                  &gEfiUdp6ServiceBindingProtocolGuid,
                  EFI_NATIVE_INTERFACE,
                  &mMockUdp6ServiceBinding
                  );
  DEBUG ((
    DEBUG_INFO,
    "MockgEfiUdp6ServiceBindingProtocolGuid: Install on gFuzzHandle: %r\n",
    Status
    ));
  if (EFI_ERROR (Status)) {
    return RETURN_DEVICE_ERROR;
  }

  return RETURN_SUCCESS;
}
