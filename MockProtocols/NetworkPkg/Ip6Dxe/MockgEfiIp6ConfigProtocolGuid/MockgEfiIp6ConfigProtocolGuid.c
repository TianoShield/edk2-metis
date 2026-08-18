/** @file MockgEfiIp6ConfigProtocolGuid.c
    HBFAplus Mock IPv6 Configuration Protocol (deferred callback pattern).

    Mock EFI_IP6_CONFIG_PROTOCOL for fuzzing drivers.
    Uses SignalOrDefer for data-change notify events.

    Copyright (c) 2025, HBFAplus Contributors. All rights reserved.
    SPDX-License-Identifier: BSD-2-Clause-Patent
**/

//=============================================================================
// UEFI Spec Audit — §28.6 (EFI IPv6 Configuration Protocol)
//
// Real UEFI: Manages IPv6 configuration data and change notifications.
// Our mock:  Stores config data in memory; uses SignalOrDefer for events.
// Deviations: None — functional stub matching spec interface.
//=============================================================================

#include <Uefi.h>
#include <Library/BaseMemoryLib.h>
#include <Library/DebugLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Protocol/Ip6.h>
#include <Protocol/Ip6Config.h>
#include <Library/FuzzContextLib.h>
#include <Library/MockDeferredSignal.h>

extern EFI_HANDLE gFuzzHandle;

//=============================================================================
// State
//=============================================================================
STATIC EFI_IP6_CONFIG_PROTOCOL mMockIp6ConfigProtocol;

STATIC EFI_IP6_CONFIG_INTERFACE_INFO mInterfaceInfo;
STATIC EFI_IP6_ADDRESS_INFO mAddressInfoStorage[1];
STATIC EFI_IP6_CONFIG_DUP_ADDR_DETECT_TRANSMITS mDadXmits;
STATIC EFI_IP6_CONFIG_POLICY mPolicy;

STATIC EFI_IP6_CONFIG_MANUAL_ADDRESS mManualAddress;
STATIC BOOLEAN mManualAddressSet = FALSE;
STATIC EFI_IPv6_ADDRESS mGateway;
STATIC BOOLEAN mGatewaySet = FALSE;
STATIC EFI_IPv6_ADDRESS mDnsServer;
STATIC BOOLEAN mDnsServerSet = FALSE;
STATIC EFI_IP6_CONFIG_INTERFACE_ID mAltInterfaceId;
STATIC BOOLEAN mAltInterfaceIdSet = FALSE;

//=============================================================================
// Data Notify Event Tracking
//=============================================================================
#define MAX_DATA_NOTIFY_REGISTRATIONS 8

typedef struct {
  EFI_IP6_CONFIG_DATA_TYPE DataType;
  EFI_EVENT Event;
  BOOLEAN InUse;
} IP6_CONFIG_NOTIFY_ENTRY;

STATIC IP6_CONFIG_NOTIFY_ENTRY mNotifyTable[MAX_DATA_NOTIFY_REGISTRATIONS];
STATIC MOCK_DEFERRED_STATE     mDeferredState;

STATIC VOID SignalNotifyEvents (EFI_IP6_CONFIG_DATA_TYPE DataType) {
  UINTN i;
  for (i = 0; i < MAX_DATA_NOTIFY_REGISTRATIONS; i++) {
    if (mNotifyTable[i].InUse && mNotifyTable[i].DataType == DataType
        && mNotifyTable[i].Event != NULL) {
      MockDeferredSchedule (&mDeferredState, mNotifyTable[i].Event);
    }
  }
}

//=============================================================================
// Protocol Functions
//=============================================================================

STATIC EFI_STATUS EFIAPI MockIp6ConfigSetData (
  IN EFI_IP6_CONFIG_PROTOCOL *This,
  IN EFI_IP6_CONFIG_DATA_TYPE DataType,
  IN UINTN DataSize, IN VOID *Data)
{
  switch (DataType) {
    case Ip6ConfigDataTypePolicy:
      if (DataSize == sizeof (EFI_IP6_CONFIG_POLICY) && Data != NULL) {
        CopyMem (&mPolicy, Data, sizeof (mPolicy));
        SignalNotifyEvents (Ip6ConfigDataTypePolicy);
        return EFI_SUCCESS;
      }
      return EFI_BAD_BUFFER_SIZE;

    case Ip6ConfigDataTypeDupAddrDetectTransmits:
      if (DataSize == sizeof (mDadXmits) && Data != NULL) {
        CopyMem (&mDadXmits, Data, sizeof (mDadXmits));
        SignalNotifyEvents (Ip6ConfigDataTypeDupAddrDetectTransmits);
        return EFI_SUCCESS;
      }
      return EFI_BAD_BUFFER_SIZE;

    case Ip6ConfigDataTypeAltInterfaceId:
      if (DataSize == sizeof (EFI_IP6_CONFIG_INTERFACE_ID) && Data != NULL) {
        CopyMem (&mAltInterfaceId, Data, sizeof (mAltInterfaceId));
        mAltInterfaceIdSet = TRUE;
        SignalNotifyEvents (Ip6ConfigDataTypeAltInterfaceId);
        return EFI_SUCCESS;
      }
      if (DataSize == 0 && Data == NULL) { mAltInterfaceIdSet = FALSE; return EFI_SUCCESS; }
      return EFI_BAD_BUFFER_SIZE;

    case Ip6ConfigDataTypeManualAddress:
      if (DataSize == sizeof (EFI_IP6_CONFIG_MANUAL_ADDRESS) && Data != NULL) {
        CopyMem (&mManualAddress, Data, sizeof (mManualAddress));
        mManualAddressSet = TRUE;
        /* Update interface info to reflect the manual address */
        CopyMem (&mAddressInfoStorage[0].Address, &mManualAddress.Address, sizeof (EFI_IPv6_ADDRESS));
        mAddressInfoStorage[0].PrefixLength = mManualAddress.PrefixLength;
        SignalNotifyEvents (Ip6ConfigDataTypeManualAddress);
        return EFI_SUCCESS;
      }
      if (DataSize == 0 && Data == NULL) { mManualAddressSet = FALSE; return EFI_SUCCESS; }
      return EFI_BAD_BUFFER_SIZE;

    case Ip6ConfigDataTypeGateway:
      if (DataSize == sizeof (EFI_IPv6_ADDRESS) && Data != NULL) {
        CopyMem (&mGateway, Data, sizeof (mGateway));
        mGatewaySet = TRUE;
        SignalNotifyEvents (Ip6ConfigDataTypeGateway);
        return EFI_SUCCESS;
      }
      if (DataSize == 0 && Data == NULL) { mGatewaySet = FALSE; return EFI_SUCCESS; }
      return EFI_BAD_BUFFER_SIZE;

    case Ip6ConfigDataTypeDnsServer:
      if (DataSize == sizeof (EFI_IPv6_ADDRESS) && Data != NULL) {
        CopyMem (&mDnsServer, Data, sizeof (mDnsServer));
        mDnsServerSet = TRUE;
        SignalNotifyEvents (Ip6ConfigDataTypeDnsServer);
        return EFI_SUCCESS;
      }
      if (DataSize == 0 && Data == NULL) { mDnsServerSet = FALSE; return EFI_SUCCESS; }
      return EFI_BAD_BUFFER_SIZE;

    default:
      return EFI_WRITE_PROTECTED;
  }
}

STATIC EFI_STATUS EFIAPI MockIp6ConfigGetData (
  IN EFI_IP6_CONFIG_PROTOCOL *This,
  IN EFI_IP6_CONFIG_DATA_TYPE DataType,
  IN OUT UINTN *DataSize, IN VOID *Data OPTIONAL)
{
  UINTN Req;
  if (DataSize == NULL) return EFI_INVALID_PARAMETER;

  switch (DataType) {
    case Ip6ConfigDataTypeInterfaceInfo:
      Req = sizeof (EFI_IP6_CONFIG_INTERFACE_INFO);
      if (*DataSize < Req) { *DataSize = Req; return EFI_BUFFER_TOO_SMALL; }
      if (Data) CopyMem (Data, &mInterfaceInfo, Req);
      *DataSize = Req; return EFI_SUCCESS;

    case Ip6ConfigDataTypePolicy:
      Req = sizeof (EFI_IP6_CONFIG_POLICY);
      if (*DataSize < Req) { *DataSize = Req; return EFI_BUFFER_TOO_SMALL; }
      if (Data) CopyMem (Data, &mPolicy, Req);
      *DataSize = Req; return EFI_SUCCESS;

    case Ip6ConfigDataTypeDupAddrDetectTransmits:
      Req = sizeof (mDadXmits);
      if (*DataSize < Req) { *DataSize = Req; return EFI_BUFFER_TOO_SMALL; }
      if (Data) CopyMem (Data, &mDadXmits, Req);
      *DataSize = Req; return EFI_SUCCESS;

    case Ip6ConfigDataTypeAltInterfaceId:
      if (!mAltInterfaceIdSet) return EFI_NOT_FOUND;
      Req = sizeof (EFI_IP6_CONFIG_INTERFACE_ID);
      if (*DataSize < Req) { *DataSize = Req; return EFI_BUFFER_TOO_SMALL; }
      if (Data) CopyMem (Data, &mAltInterfaceId, Req);
      *DataSize = Req; return EFI_SUCCESS;

    case Ip6ConfigDataTypeManualAddress:
      if (!mManualAddressSet) return EFI_NOT_FOUND;
      Req = sizeof (EFI_IP6_CONFIG_MANUAL_ADDRESS);
      if (*DataSize < Req) { *DataSize = Req; return EFI_BUFFER_TOO_SMALL; }
      if (Data) CopyMem (Data, &mManualAddress, Req);
      *DataSize = Req; return EFI_SUCCESS;

    case Ip6ConfigDataTypeGateway:
      if (!mGatewaySet) return EFI_NOT_FOUND;
      Req = sizeof (EFI_IPv6_ADDRESS);
      if (*DataSize < Req) { *DataSize = Req; return EFI_BUFFER_TOO_SMALL; }
      if (Data) CopyMem (Data, &mGateway, Req);
      *DataSize = Req; return EFI_SUCCESS;

    case Ip6ConfigDataTypeDnsServer:
      if (!mDnsServerSet) return EFI_NOT_FOUND;
      Req = sizeof (EFI_IPv6_ADDRESS);
      if (*DataSize < Req) { *DataSize = Req; return EFI_BUFFER_TOO_SMALL; }
      if (Data) CopyMem (Data, &mDnsServer, Req);
      *DataSize = Req; return EFI_SUCCESS;

    default:
      return EFI_NOT_FOUND;
  }
}

STATIC EFI_STATUS EFIAPI MockIp6ConfigRegisterDataNotify (
  IN EFI_IP6_CONFIG_PROTOCOL *This,
  IN EFI_IP6_CONFIG_DATA_TYPE DataType,
  IN EFI_EVENT Event)
{
  UINTN i;
  if (Event == NULL) return EFI_INVALID_PARAMETER;

  for (i = 0; i < MAX_DATA_NOTIFY_REGISTRATIONS; i++) {
    if (mNotifyTable[i].InUse && mNotifyTable[i].DataType == DataType
        && mNotifyTable[i].Event == Event) return EFI_ACCESS_DENIED;
  }
  for (i = 0; i < MAX_DATA_NOTIFY_REGISTRATIONS; i++) {
    if (!mNotifyTable[i].InUse) {
      mNotifyTable[i].DataType = DataType;
      mNotifyTable[i].Event = Event;
      mNotifyTable[i].InUse = TRUE;
      return EFI_SUCCESS;
    }
  }
  return EFI_OUT_OF_RESOURCES;
}

STATIC EFI_STATUS EFIAPI MockIp6ConfigUnregisterDataNotify (
  IN EFI_IP6_CONFIG_PROTOCOL *This,
  IN EFI_IP6_CONFIG_DATA_TYPE DataType,
  IN EFI_EVENT Event)
{
  UINTN i;
  if (Event == NULL) return EFI_INVALID_PARAMETER;

  for (i = 0; i < MAX_DATA_NOTIFY_REGISTRATIONS; i++) {
    if (mNotifyTable[i].InUse && mNotifyTable[i].DataType == DataType
        && mNotifyTable[i].Event == Event) {
      mNotifyTable[i].InUse = FALSE;
      mNotifyTable[i].Event = NULL;
      return EFI_SUCCESS;
    }
  }
  return EFI_NOT_FOUND;
}

//=============================================================================
// Internal reset -- registered with MockProtocolRegisterReset
//=============================================================================
STATIC VOID EFIAPI ResetState (VOID) {
  MockDeferredReset (&mDeferredState);
  ZeroMem (mNotifyTable, sizeof (mNotifyTable));
  mManualAddressSet = FALSE;
  mGatewaySet = FALSE;
  mDnsServerSet = FALSE;
  mAltInterfaceIdSet = FALSE;
  mPolicy = Ip6ConfigPolicyAutomatic;
  mDadXmits.DupAddrDetectTransmits = 1;
  /* Restore defaults */
  ZeroMem (&mInterfaceInfo, sizeof (mInterfaceInfo));
  ZeroMem (mAddressInfoStorage, sizeof (mAddressInfoStorage));
  mAddressInfoStorage[0].Address.Addr[0] = 0xFE;
  mAddressInfoStorage[0].Address.Addr[1] = 0x80;
  mAddressInfoStorage[0].Address.Addr[15] = 0x01;
  mAddressInfoStorage[0].PrefixLength = 64;
  mInterfaceInfo.AddressInfo = mAddressInfoStorage;
  mInterfaceInfo.AddressInfoCount = 1;
}

//=============================================================================
// Constructor
//=============================================================================
RETURN_STATUS EFIAPI MockgEfiIp6ConfigProtocolGuidConstructor (VOID) {
  EFI_STATUS Status;

  if ((gBS == NULL) || (gFuzzHandle == NULL)) {
    DEBUG ((DEBUG_WARN, "MockgEfiIp6ConfigProtocolGuid: gBS or gFuzzHandle is NULL\n"));
    return RETURN_SUCCESS;
  }

  ResetState ();
  MockProtocolRegisterReset (ResetState);

  mMockIp6ConfigProtocol.SetData = MockIp6ConfigSetData;
  mMockIp6ConfigProtocol.GetData = MockIp6ConfigGetData;
  mMockIp6ConfigProtocol.RegisterDataNotify = MockIp6ConfigRegisterDataNotify;
  mMockIp6ConfigProtocol.UnregisterDataNotify = MockIp6ConfigUnregisterDataNotify;

  Status = gBS->InstallProtocolInterface (
    &gFuzzHandle, &gEfiIp6ConfigProtocolGuid,
    EFI_NATIVE_INTERFACE, &mMockIp6ConfigProtocol);
  DEBUG ((DEBUG_INFO, "MockgEfiIp6ConfigProtocolGuid: Install %r\n", Status));
  if (EFI_ERROR (Status)) {
    return RETURN_DEVICE_ERROR;
  }

  return RETURN_SUCCESS;
}
