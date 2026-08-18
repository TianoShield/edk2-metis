/** @file MockgEfiIp6ServiceBindingProtocolGuid.c
    HBFAplus Mock IP6 Service Binding Protocol Implementation.

    CreateChild → *ChildHandle = gFuzzHandle.
    DestroyChild → no-op SUCCESS.

    Copyright (c) 2025, HBFAplus Contributors. All rights reserved.
    SPDX-License-Identifier: BSD-2-Clause-Patent
**/

//=============================================================================
// UEFI Spec Audit — §28.2 (EFI IP6 Service Binding Protocol)
//
// Real UEFI: Service Binding provides CreateChild/DestroyChild to
//            manage per-flow IPv6 child driver instances.
// Our mock:  CreateChild returns gFuzzHandle; DestroyChild is a no-op.
// Deviations: None — minimal stub matching spec interface.
//=============================================================================

#include <Uefi.h>
#include <Library/BaseLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/DebugLib.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Protocol/ServiceBinding.h>
#include <Protocol/Ip6.h>
#include <Library/FuzzContextLib.h>
STATIC EFI_SERVICE_BINDING_PROTOCOL  mMockIp6ServiceBinding;
STATIC UINT32                        mCreateChildCount  = 0;
STATIC UINT32                        mDestroyChildCount = 0;

extern EFI_HANDLE gFuzzHandle;

STATIC
EFI_STATUS
EFIAPI
MockIp6SbCreateChild (
  IN     EFI_SERVICE_BINDING_PROTOCOL  *This,
  IN OUT EFI_HANDLE                    *ChildHandle
  )
{
  if (ChildHandle == NULL) {
    return EFI_INVALID_PARAMETER;
  }
  DEBUG ((DEBUG_INFO, "MockIp6SB: CreateChild → gFuzzHandle\n"));
  *ChildHandle = gFuzzHandle;
  mCreateChildCount++;
  return EFI_SUCCESS;
}

STATIC
EFI_STATUS
EFIAPI
MockIp6SbDestroyChild (
  IN EFI_SERVICE_BINDING_PROTOCOL  *This,
  IN EFI_HANDLE                    ChildHandle
  )
{
  DEBUG ((DEBUG_INFO, "MockIp6SB: DestroyChild\n"));
  mDestroyChildCount++;
  return EFI_SUCCESS;
}

STATIC VOID EFIAPI ResetState (VOID) { mCreateChildCount = 0; mDestroyChildCount = 0; }
UINTN EFIAPI MockIp6SBGetCreateCount (VOID) { return mCreateChildCount; }
UINTN EFIAPI MockIp6SBGetDestroyCount (VOID) { return mDestroyChildCount; }

RETURN_STATUS
EFIAPI
MockgEfiIp6ServiceBindingProtocolGuidConstructor (
  VOID
  )
{
  EFI_STATUS  Status;

  DEBUG ((DEBUG_INFO, "MockgEfiIp6ServiceBindingProtocolGuid: Constructor\n"));

  ResetState ();
  MockProtocolRegisterReset (ResetState);

  mMockIp6ServiceBinding.CreateChild  = MockIp6SbCreateChild;
  mMockIp6ServiceBinding.DestroyChild = MockIp6SbDestroyChild;

  if ((gBS == NULL) || (gFuzzHandle == NULL)) {
    return RETURN_SUCCESS;
  }

  Status = gBS->InstallProtocolInterface (
                  &gFuzzHandle,
                  &gEfiIp6ServiceBindingProtocolGuid,
                  EFI_NATIVE_INTERFACE,
                  &mMockIp6ServiceBinding
                  );
  DEBUG ((DEBUG_INFO, "MockgEfiIp6ServiceBindingProtocolGuid: Install: %r\n", Status));
  if (EFI_ERROR (Status)) {
    return RETURN_DEVICE_ERROR;
  }

  return RETURN_SUCCESS;
}
