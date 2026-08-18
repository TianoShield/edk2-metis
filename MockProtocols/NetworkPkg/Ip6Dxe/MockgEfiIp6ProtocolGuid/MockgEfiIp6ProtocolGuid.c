/** @file MockgEfiIp6ProtocolGuid.c
    HBFAplus Mock IP6 Protocol Implementation.

    Mock EFI_IP6_PROTOCOL for fuzzing drivers that send/receive IPv6 datagrams
    (Udp6Dxe, TcpDxe, etc.).

    Behaviour:
      - Configure: stores config, returns SUCCESS; NULL resets
      - GetModeData: returns stored config + mode data with minimal defaults
      - Groups/Routes/Neighbors: no-op SUCCESS
      - Transmit: signals completion token with fuzz-controlled status
      - Receive: builds EFI_IP6_RECEIVE_DATA with IPv6 header + payload
                 from fuzz buffer, signals completion token
      - Cancel: cancels pending tokens with EFI_ABORTED
      - Poll: no-op SUCCESS

    Fuzz data consumption:
      Transmit: 1 byte -> completion status (0=SUCCESS, 1=NET_UNREACHABLE,
                2=TIMEOUT, 3=ABORTED)
      Receive:  2 bytes -> payload length hint
                1 byte  -> NextHeader (protocol number)
                N bytes -> payload data

    Copyright (c) 2025, HBFAplus Contributors. All rights reserved.
    SPDX-License-Identifier: BSD-2-Clause-Patent
**/

//=============================================================================
// UEFI Spec Audit — §28.2 (EFI IPv6 Protocol)
//
// Real UEFI: IP6 provides connectionless IPv6 datagram services including
//   routing, neighbor discovery, fragment reassembly/segmentation,
//   multicast group management, and extension header processing.
// Our mock:  Fuzz-data-driven.  Configure stores caller config and returns
//   SUCCESS.  GetModeData returns hardcoded minimal defaults plus stored
//   config.  Receive builds an EFI_IP6_RECEIVE_DATA with a synthetic IPv6
//   header and payload sourced entirely from fuzz bytes.  Transmit signals
//   a fuzz-controlled completion status.
// Deviations:
//   1. No routing table — Routes() is a no-op SUCCESS.  Fuzzing targets
//      upper-layer consumers, not the IP routing engine.
//   2. No fragment reassembly — each Receive delivers a single complete
//      packet.  Consumers see reassembled data in real UEFI too.
//   3. GetModeData returns hardcoded config — sufficient for consumer init.
//   4. Groups/Neighbors are no-ops — no neighbor discovery or multicast.
// Corner cases:
//   - Fuzz data exhaustion during Receive yields a zero-length payload.
//   - NextHeader in the synthetic header is fuzz-controlled and may not
//     match what the consumer expects.
//=============================================================================

#include <Uefi.h>
#include <Library/BaseLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/DebugLib.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Protocol/Ip6.h>
#include <Library/FuzzContextLib.h>
#include <Library/MockDeferredSignal.h>
//=============================================================================
// Module-scope state
//=============================================================================

STATIC EFI_IP6_PROTOCOL       mMockIp6Protocol;
STATIC EFI_IP6_CONFIG_DATA    mMockIp6Config;
STATIC BOOLEAN                mMockIp6Configured = FALSE;
STATIC UINT32                 mMockIp6TransmitCount = 0;
STATIC UINT32                 mMockIp6ReceiveCount = 0;

//
// Default source/destination addresses for received packets
//
STATIC EFI_IPv6_ADDRESS mDefaultIp6Source = {
  { 0xFE, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01 }
};

STATIC EFI_IPv6_ADDRESS mDefaultIp6Dest = {
  { 0xFE, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x02 }
};

extern EFI_HANDLE gFuzzHandle;

STATIC MOCK_DEFERRED_STATE  mDeferredState;

//=============================================================================
// Internal helpers
//=============================================================================

/**
  Resolve the effective fuzz context for this protocol.

  Checks the protocol context registry for a harness-provided override;
  falls back to the cached global pool pointer.

  @return  Active fuzz context, or NULL if none available.
**/
STATIC
MOCK_FUZZ_CONTEXT *
ResolveContext (
  VOID
  )
{
  MOCK_FUZZ_CONTEXT  *Override;

  Override = MockFuzzContextGetProtocolContext (&gEfiIp6ProtocolGuid);
  return (Override != NULL) ? Override : MockFuzzContextGetPool ();
}

STATIC
VOID
ConsumeFuzzBytes (
  OUT UINT8   *Buffer,
  IN  UINTN   RequestedSize,
  OUT UINTN   *ActualSize
  )
{
  MOCK_FUZZ_CONTEXT  *Ctx;
  UINT8              *Src;
  UINTN              Available;

  Ctx = ResolveContext ();
  if ((Ctx == NULL) ||
      (Ctx->Buffer == NULL) ||
      (Ctx->Size == 0))
  {
    //
    // Deterministic fallback: fill with 0xAA
    //
    SetMem (Buffer, RequestedSize, 0xAA);
    *ActualSize = RequestedSize;
    return;
  }

  Available = MockFuzzContextRemaining (Ctx);
  if (Available == 0) {
    //
    // Fuzz data exhausted -- fill with zeros
    //
    ZeroMem (Buffer, RequestedSize);
    *ActualSize = 0;
    return;
  }

  if (RequestedSize > Available) {
    RequestedSize = Available;
  }

  Src = MockFuzzContextConsume (Ctx, RequestedSize);
  if (Src != NULL) {
    CopyMem (Buffer, Src, RequestedSize);
    *ActualSize = RequestedSize;
  } else {
    ZeroMem (Buffer, RequestedSize);
    *ActualSize = 0;
  }
}



//=============================================================================
// Mock protocol function implementations
//=============================================================================

/**
  Mock GetModeData -- returns the stored IPv6 config and mode data.
**/
STATIC
EFI_STATUS
EFIAPI
MockIp6GetModeData (
  IN  EFI_IP6_PROTOCOL                 *This,
  OUT EFI_IP6_MODE_DATA                *Ip6ModeData     OPTIONAL,
  OUT EFI_MANAGED_NETWORK_CONFIG_DATA  *MnpConfigData   OPTIONAL,
  OUT EFI_SIMPLE_NETWORK_MODE          *SnpModeData     OPTIONAL
  )
{
  DEBUG ((DEBUG_VERBOSE, "MockIp6: GetModeData\n"));

  if (Ip6ModeData != NULL) {
    ZeroMem (Ip6ModeData, sizeof (EFI_IP6_MODE_DATA));
    Ip6ModeData->IsStarted    = TRUE;
    Ip6ModeData->IsConfigured = mMockIp6Configured;
    Ip6ModeData->MaxPacketSize = 1500;

    if (mMockIp6Configured) {
      CopyMem (&Ip6ModeData->ConfigData, &mMockIp6Config, sizeof (EFI_IP6_CONFIG_DATA));

      //
      // Provide a single address entry
      // AUDIT-FIX: Only set AddressCount=1 when allocation succeeds.
      // Consumer would NULL-deref on AddressList if AddressCount=1 but
      // AllocateZeroPool failed.
      //
      Ip6ModeData->AddressList = AllocateZeroPool (sizeof (EFI_IP6_ADDRESS_INFO));
      if (Ip6ModeData->AddressList != NULL) {
        Ip6ModeData->AddressCount = 1;
        CopyMem (&Ip6ModeData->AddressList[0].Address, &mMockIp6Config.StationAddress, sizeof (EFI_IPv6_ADDRESS));
        Ip6ModeData->AddressList[0].PrefixLength = 64;
      }
    }
  }

  if (MnpConfigData != NULL) {
    ZeroMem (MnpConfigData, sizeof (EFI_MANAGED_NETWORK_CONFIG_DATA));
  }

  if (SnpModeData != NULL) {
    ZeroMem (SnpModeData, sizeof (EFI_SIMPLE_NETWORK_MODE));
    SnpModeData->State = EfiSimpleNetworkInitialized;
  }

  return EFI_SUCCESS;
}

/**
  Mock Configure -- stores config data for later retrieval.
  Passing NULL resets to unconfigured state and cancels pending tokens.
**/
STATIC
EFI_STATUS
EFIAPI
MockIp6Configure (
  IN EFI_IP6_PROTOCOL     *This,
  IN EFI_IP6_CONFIG_DATA  *Ip6ConfigData  OPTIONAL
  )
{
  DEBUG ((DEBUG_VERBOSE, "MockIp6: Configure (data=%p)\n", Ip6ConfigData));

  if (Ip6ConfigData == NULL) {
    //
    // Reset to unconfigured -- cancel all deferred tokens first
    //
    MockDeferredCancelAll (&mDeferredState);
    ZeroMem (&mMockIp6Config, sizeof (mMockIp6Config));
    mMockIp6Configured = FALSE;
    return EFI_SUCCESS;
  }

  CopyMem (&mMockIp6Config, Ip6ConfigData, sizeof (EFI_IP6_CONFIG_DATA));
  mMockIp6Configured = TRUE;

  return EFI_SUCCESS;
}

STATIC
EFI_STATUS
EFIAPI
MockIp6Groups (
  IN EFI_IP6_PROTOCOL  *This,
  IN BOOLEAN           JoinFlag,
  IN EFI_IPv6_ADDRESS  *GroupAddress  OPTIONAL
  )
{
  DEBUG ((DEBUG_VERBOSE, "MockIp6: Groups (Join=%d)\n", JoinFlag));
  return EFI_SUCCESS;
}

STATIC
EFI_STATUS
EFIAPI
MockIp6Routes (
  IN EFI_IP6_PROTOCOL  *This,
  IN BOOLEAN           DeleteRoute,
  IN EFI_IPv6_ADDRESS  *Destination    OPTIONAL,
  IN UINT8             PrefixLength,
  IN EFI_IPv6_ADDRESS  *GatewayAddress OPTIONAL
  )
{
  DEBUG ((DEBUG_VERBOSE, "MockIp6: Routes (Delete=%d)\n", DeleteRoute));
  return EFI_SUCCESS;
}

STATIC
EFI_STATUS
EFIAPI
MockIp6Neighbors (
  IN EFI_IP6_PROTOCOL  *This,
  IN BOOLEAN           DeleteFlag,
  IN EFI_IPv6_ADDRESS  *TargetIp6Address,
  IN EFI_MAC_ADDRESS   *TargetLinkAddress,
  IN UINT32            Timeout,
  IN BOOLEAN           Override
  )
{
  DEBUG ((DEBUG_VERBOSE, "MockIp6: Neighbors (Delete=%d)\n", DeleteFlag));
  return EFI_SUCCESS;
}

/**
  Mock Transmit -- consume 1 fuzz byte for status, signal completion token.
  Supports deferred signaling when advance context is active.
**/
STATIC
EFI_STATUS
EFIAPI
MockIp6Transmit (
  IN EFI_IP6_PROTOCOL          *This,
  IN EFI_IP6_COMPLETION_TOKEN  *Token
  )
{
  UINT8  FuzzStatus;

  DEBUG ((DEBUG_VERBOSE, "MockIp6: Transmit (token=%p)\n", Token));

  if (!mMockIp6Configured) {
    return EFI_NOT_STARTED;
  }

  if (Token == NULL) {
    return EFI_INVALID_PARAMETER;
  }

  if (Token->Event == NULL) {
    return EFI_INVALID_PARAMETER;
  }

  mMockIp6TransmitCount++;

  //
  // Consume 1 fuzz byte for TX completion status
  //
  FuzzStatus = 0;
  {
    MOCK_FUZZ_CONTEXT  *TxCtx = ResolveContext ();
    if (TxCtx != NULL && MockFuzzContextRemaining (TxCtx) >= 1) {
      FuzzStatus = MockFuzzContextGetU8 (TxCtx);
    }
  }

  switch (FuzzStatus) {
    case 1:  Token->Status = EFI_NETWORK_UNREACHABLE; break;
    case 2:  Token->Status = EFI_TIMEOUT;             break;
    case 3:  Token->Status = EFI_ABORTED;             break;
    default: Token->Status = EFI_SUCCESS;             break;
  }

  //
  // Signal completion immediately — TX has no incoming data to defer.
  //
  MockDeferredSchedule (&mDeferredState, Token->Event);

  return EFI_SUCCESS;
}

/**
  Mock Receive -- builds EFI_IP6_RECEIVE_DATA with a fake IPv6 header
  and payload from fuzz buffer.  Supports deferred signaling.

  Fuzz byte budget:
    2 bytes: payload length hint
    1 byte:  NextHeader (protocol number)
    N bytes: payload data
**/
STATIC
EFI_STATUS
EFIAPI
MockIp6Receive (
  IN EFI_IP6_PROTOCOL          *This,
  IN EFI_IP6_COMPLETION_TOKEN  *Token
  )
{
  EFI_IP6_RECEIVE_DATA  *RxData;
  EFI_IP6_HEADER        *Ip6Hdr;
  UINT8                 *PayloadBuf;
  UINTN                 PayloadSize;
  UINTN                 Consumed;
  UINT8                 NextHeader;

  DEBUG ((DEBUG_VERBOSE, "MockIp6: Receive (token=%p)\n", Token));

  if (!mMockIp6Configured) {
    return EFI_NOT_STARTED;
  }

  if (Token == NULL) {
    return EFI_INVALID_PARAMETER;
  }

  if (Token->Event == NULL) {
    return EFI_INVALID_PARAMETER;
  }

  mMockIp6ReceiveCount++;

  //
  // 1. Consume 2-byte payload length hint
  //
  {
    UINT8  LenHint[2] = { 0 };
    ConsumeFuzzBytes (LenHint, sizeof (LenHint), &Consumed);
    if (Consumed == 0) {
      Token->Packet.RxData = NULL;
      Token->Status = EFI_ABORTED;
      MockDeferredSchedule (&mDeferredState, Token->Event);
      return EFI_SUCCESS;
    }
    PayloadSize = (UINTN)LenHint[0] | ((UINTN)LenHint[1] << 8);
    if (PayloadSize == 0) {
      PayloadSize = 64;
    }
    if (PayloadSize > 1460) {
      PayloadSize = 1460;  // IPv6 payload max within MTU
    }
  }

  //
  // 2. Consume 1-byte NextHeader (overrides config default)
  //
  NextHeader = 17;  // UDP default
  {
    UINT8 Nh[1];
    ConsumeFuzzBytes (Nh, 1, &Consumed);
    if (Consumed > 0) {
      NextHeader = Nh[0];
    }
  }

  //
  // 3. Allocate RxData + IPv6 header + payload
  //
  {
    UINTN TotalAlloc = sizeof (EFI_IP6_RECEIVE_DATA) + sizeof (EFI_IP6_HEADER) + PayloadSize;
    RxData = AllocateZeroPool (TotalAlloc);
    if (RxData == NULL) {
      Token->Status = EFI_OUT_OF_RESOURCES;
      Token->Packet.RxData = NULL;
      MockDeferredSchedule (&mDeferredState, Token->Event);
      return EFI_SUCCESS;
    }
  }

  Ip6Hdr = (EFI_IP6_HEADER *)((UINT8 *)RxData + sizeof (EFI_IP6_RECEIVE_DATA));
  PayloadBuf = (UINT8 *)Ip6Hdr + sizeof (EFI_IP6_HEADER);

  //
  // 4. Fill payload from fuzz
  //
  ConsumeFuzzBytes (PayloadBuf, PayloadSize, &Consumed);
  if (Consumed < PayloadSize) {
    PayloadSize = Consumed;
  }

  //
  // 5. Build IPv6 header
  //
  Ip6Hdr->Version       = 6;
  Ip6Hdr->TrafficClassH = 0;
  Ip6Hdr->TrafficClassL = 0;
  Ip6Hdr->FlowLabelH    = 0;
  Ip6Hdr->FlowLabelL    = 0;
  Ip6Hdr->PayloadLength = SwapBytes16 ((UINT16)PayloadSize);
  Ip6Hdr->NextHeader    = NextHeader;
  Ip6Hdr->HopLimit      = 64;
  CopyMem (&Ip6Hdr->SourceAddress, &mDefaultIp6Source, sizeof (EFI_IPv6_ADDRESS));

  if (mMockIp6Configured) {
    CopyMem (&Ip6Hdr->DestinationAddress, &mMockIp6Config.StationAddress, sizeof (EFI_IPv6_ADDRESS));
  } else {
    CopyMem (&Ip6Hdr->DestinationAddress, &mDefaultIp6Dest, sizeof (EFI_IPv6_ADDRESS));
  }

  //
  // 6. Populate RxData
  //
  RxData->HeaderLength  = (UINT32)sizeof (EFI_IP6_HEADER);
  RxData->Header        = Ip6Hdr;
  RxData->DataLength    = (UINT32)PayloadSize;
  RxData->FragmentCount = 1;
  RxData->FragmentTable[0].FragmentLength = (UINT32)PayloadSize;
  RxData->FragmentTable[0].FragmentBuffer = PayloadBuf;

  //
  // Create a RecycleSignal event.  IpIoListenHandlerDpc (and IpIoExtFree
  // via NetbufFree) signals this to tell IP that the receive buffer can be
  // recycled.  Bare event (no callback) so it does NOT auto-register with
  // MockEventAdvanceContext.  RxData memory leaks — OK for AFL fork-server.
  //
  {
    EFI_EVENT  RecycleEvent = NULL;
    gBS->CreateEvent (0, TPL_CALLBACK, NULL, NULL, &RecycleEvent);
    RxData->RecycleSignal = RecycleEvent;
  }

  Token->Packet.RxData = RxData;
  Token->Status = EFI_SUCCESS;

  //
  // 7. Defer completion — fires during next AdvanceTime tick.
  //
  MockDeferredSchedule (&mDeferredState, Token->Event);

  return EFI_SUCCESS;
}

/**
  Mock Cancel -- cancel pending async tokens.
  NULL token cancels all; specific token cancels that one only.

  @retval EFI_SUCCESS     Tokens cancelled
  @retval EFI_NOT_STARTED Protocol not configured
  @retval EFI_NOT_FOUND   Specific token not found in pending list
**/
STATIC
EFI_STATUS
EFIAPI
MockIp6Cancel (
  IN EFI_IP6_PROTOCOL          *This,
  IN EFI_IP6_COMPLETION_TOKEN  *Token  OPTIONAL
  )
{
  DEBUG ((DEBUG_VERBOSE, "MockIp6: Cancel (token=%p)\n", Token));

  if (!mMockIp6Configured) {
    return EFI_NOT_STARTED;
  }

  if (Token == NULL) {
    MockDeferredCancelAll (&mDeferredState);
    return EFI_SUCCESS;
  }

  //
  // Cancel specific token
  //
  return MockDeferredCancel (&mDeferredState, Token->Event);
}

STATIC
EFI_STATUS
EFIAPI
MockIp6Poll (
  IN EFI_IP6_PROTOCOL  *This
  )
{
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
  mMockIp6Configured    = FALSE;
  ZeroMem (&mMockIp6Config, sizeof (mMockIp6Config));
  mMockIp6TransmitCount = 0;
  mMockIp6ReceiveCount  = 0;
  MockDeferredReset (&mDeferredState);
}

//=============================================================================
// Library Constructor
//=============================================================================

RETURN_STATUS
EFIAPI
MockgEfiIp6ProtocolGuidConstructor (
  VOID
  )
{
  EFI_STATUS  Status;

  DEBUG ((DEBUG_INFO, "MockgEfiIp6ProtocolGuid: Constructor\n"));

  mMockIp6Protocol.GetModeData = MockIp6GetModeData;
  mMockIp6Protocol.Configure   = MockIp6Configure;
  mMockIp6Protocol.Groups      = MockIp6Groups;
  mMockIp6Protocol.Routes      = MockIp6Routes;
  mMockIp6Protocol.Neighbors   = MockIp6Neighbors;
  mMockIp6Protocol.Transmit    = MockIp6Transmit;
  mMockIp6Protocol.Receive     = MockIp6Receive;
  mMockIp6Protocol.Cancel      = MockIp6Cancel;
  mMockIp6Protocol.Poll        = MockIp6Poll;

  ResetState ();
  MockProtocolRegisterReset (ResetState);

  if ((gBS == NULL) || (gFuzzHandle == NULL)) {
    DEBUG ((DEBUG_WARN, "MockgEfiIp6ProtocolGuid: gBS or gFuzzHandle NULL\n"));
    return RETURN_SUCCESS;
  }

  Status = gBS->InstallProtocolInterface (
                  &gFuzzHandle,
                  &gEfiIp6ProtocolGuid,
                  EFI_NATIVE_INTERFACE,
                  &mMockIp6Protocol
                  );
  DEBUG ((DEBUG_INFO, "MockgEfiIp6ProtocolGuid: Install: %r\n", Status));
  if (EFI_ERROR (Status)) {
    return RETURN_DEVICE_ERROR;
  }

  return RETURN_SUCCESS;
}
