/** @file MockgEfiUdp6ProtocolGuid.c
    HBFAplus Mock UDP6 Protocol Implementation.

    Mock EFI_UDP6_PROTOCOL for fuzzing drivers that send/receive UDP6 packets
    (Dhcp6Dxe, DnsDxe, etc.).

    Architecture — Deferred completion via direct signaling:
      In real edk2, Udp6->Receive() queues the token in an RxTokens map and
      returns immediately.  The actual data delivery happens asynchronously
      when a network packet arrives and the driver signals the token's event.
      Similarly, Udp6->Transmit() queues the token and signals completion
      when the IP layer finishes sending.

      This mock replicates that asynchronous pattern:
        - Receive(): consumes fuzz bytes to build EFI_UDP6_RECEIVE_DATA,
          populates Token->Packet.RxData, but does NOT signal Token->Event.
          The token's event (created by UdpIoCreateRxToken with
          EVT_NOTIFY_SIGNAL + callback) is auto-registered with the event
          advance by CoreCreateEvent.  The harness's MockFuzzContextAdvanceTime()
          call fires the event, which triggers the consumer's completion
          callback — exactly like real UEFI async I/O.
        - Transmit(): sets fuzz-controlled completion status on the token
          but defers signaling to the direct signaling.

      This eliminates the infinite recursion problem where:
        Receive → SignalEvent → DPC → callback → re-arm Receive → loop
      because Receive only prepares data; the event fires via direct signaling
      in a separate, non-recursive control path.

    Behaviour:
      - Configure: stores config, returns SUCCESS; NULL resets and cancels
      - GetModeData: returns stored config; returns NOT_STARTED if unconfigured
      - Groups: no-op SUCCESS (join/leave multicast)
      - Transmit: deferred completion (direct, fuzz-controlled status)
      - Receive: deferred completion (direct, fuzz-built RxData)
      - Cancel: aborts pending tokens, signals EFI_ABORTED
      - Poll: no-op SUCCESS

    Fuzz data consumption:
      Transmit: 1 byte → completion status selector
      Receive:  2 bytes → LE16 payload length hint, N bytes → payload data

    Copyright (c) 2025, HBFAplus Contributors. All rights reserved.
    SPDX-License-Identifier: BSD-2-Clause-Patent
**/

//=============================================================================
// UEFI Spec Audit — §29.2 (EFI UDP6 Protocol)
//
// Real UEFI: UDP6 provides connectionless, unreliable datagram services
//   over IPv6.  It performs port demultiplexing, optional checksum
//   verification, and manages receive/transmit token queues with
//   asynchronous completion via events.
// Our mock:  Fuzz-data-driven with deferred completion via direct signaling.
//   Receive builds EFI_UDP6_RECEIVE_DATA from fuzz bytes.  Transmit
//   picks a fuzz-controlled completion status.  Both use direct signaling pattern
//   to avoid re-entrant callback recursion.
// Deviations:
//   1. No actual UDP/IP stack — no checksum verification, no port
//      demultiplexing.  OK because we test the consumer's handling of
//      arbitrary datagram content.
//   2. RecycleSignal creates a bare event (not a real recycle mechanism).
//      Consumers that call gBS->SignalEvent on the recycle event will
//      succeed but no buffer is actually recycled.
//   3. No fragmentation/reassembly at the UDP layer — each Receive
//      delivers one complete datagram.
// Corner cases:
//   - Fuzz data exhaustion returns a zero-length datagram.
//   - Rapid Cancel after Receive may race with direct delivery.
//   - Session header fields (src/dst port, addr) are synthetic and may
//     not match the configured remote endpoint.
//=============================================================================

#include <Uefi.h>
#include <Library/BaseLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/DebugLib.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Protocol/Udp6.h>
#include <Library/FuzzContextLib.h>
#include <Library/MockDeferredSignal.h>

//=============================================================================
// Module-scope state
//=============================================================================

STATIC EFI_UDP6_PROTOCOL         mMockUdp6Protocol;
STATIC EFI_UDP6_CONFIG_DATA      mMockUdp6Config;
STATIC BOOLEAN                   mMockUdp6Configured    = FALSE;
STATIC UINT32                    mMockUdp6TransmitCount = 0;
STATIC UINT32                    mMockUdp6ReceiveCount  = 0;
STATIC MOCK_DEFERRED_STATE       mDeferredState;

//
// Default session data for received packets
//
STATIC EFI_IPv6_ADDRESS mDefaultSourceAddress = {
  { 0xFE, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x02 }
};

extern EFI_HANDLE          gFuzzHandle;

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

  Override = MockFuzzContextGetProtocolContext (&gEfiUdp6ProtocolGuid);
  return (Override != NULL) ? Override : MockFuzzContextGetPool ();
}

/**
  Consume up to RequestedSize bytes from the fuzz buffer.

  If the fuzz context is NULL or empty and Size is 0, uses a deterministic
  fallback (0xAA fill) so unit tests without fuzz data still work.  If the
  fuzz buffer is exhausted, zeroes the output and returns 0.

  @param[out] Buffer         Destination buffer.
  @param[in]  RequestedSize  Bytes to consume.
  @param[out] ActualSize     Bytes actually consumed (may be less than requested).
**/
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
  Mock GetModeData - returns the stored UDP6 config.
**/
STATIC
EFI_STATUS
EFIAPI
MockUdp6GetModeData (
  IN  EFI_UDP6_PROTOCOL                *This,
  OUT EFI_UDP6_CONFIG_DATA             *Udp6ConfigData   OPTIONAL,
  OUT EFI_IP6_MODE_DATA                *Ip6ModeData      OPTIONAL,
  OUT EFI_MANAGED_NETWORK_CONFIG_DATA  *MnpConfigData    OPTIONAL,
  OUT EFI_SIMPLE_NETWORK_MODE          *SnpModeData      OPTIONAL
  )
{
  DEBUG ((DEBUG_VERBOSE, "MockUdp6: GetModeData\n"));

  if (Udp6ConfigData != NULL) {
    if (!mMockUdp6Configured) {
      return EFI_NOT_STARTED;
    }
    CopyMem (Udp6ConfigData, &mMockUdp6Config, sizeof (EFI_UDP6_CONFIG_DATA));
  }

  //
  // Ip6ModeData, MnpConfigData, SnpModeData - provide minimal defaults
  //
  if (Ip6ModeData != NULL) {
    ZeroMem (Ip6ModeData, sizeof (EFI_IP6_MODE_DATA));
    Ip6ModeData->IsStarted    = TRUE;
    Ip6ModeData->IsConfigured = mMockUdp6Configured;
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
  Mock Configure - stores config data for later retrieval.
  Passing NULL resets to unconfigured state and cancels all pending tokens
  (matching real edk2 Udp6FlushTokens behaviour).
**/
STATIC
EFI_STATUS
EFIAPI
MockUdp6Configure (
  IN EFI_UDP6_PROTOCOL     *This,
  IN EFI_UDP6_CONFIG_DATA  *UdpConfigData  OPTIONAL
  )
{
  DEBUG ((DEBUG_VERBOSE, "MockUdp6: Configure (data=%p)\n", UdpConfigData));

  if (UdpConfigData == NULL) {
    //
    // Reset to unconfigured — cancel all pending tokens first
    // (matches real edk2 Udp6FlushTokens on Configure(NULL))
    //
    MockDeferredCancelAll (&mDeferredState);
    ZeroMem (&mMockUdp6Config, sizeof (mMockUdp6Config));
    mMockUdp6Configured = FALSE;
    return EFI_SUCCESS;
  }

  CopyMem (&mMockUdp6Config, UdpConfigData, sizeof (EFI_UDP6_CONFIG_DATA));
  mMockUdp6Configured = TRUE;

  return EFI_SUCCESS;
}

/**
  Mock Groups - join/leave multicast.  No-op for fuzzing.
**/
STATIC
EFI_STATUS
EFIAPI
MockUdp6Groups (
  IN EFI_UDP6_PROTOCOL  *This,
  IN BOOLEAN            JoinFlag,
  IN EFI_IPv6_ADDRESS   *MulticastAddress  OPTIONAL
  )
{
  DEBUG ((DEBUG_VERBOSE, "MockUdp6: Groups (Join=%d)\n", JoinFlag));
  return EFI_SUCCESS;
}

/**
  Mock Transmit - sets fuzz-controlled completion status, defers signaling.

  Real edk2 Udp6Transmit queues the token, IP6 sends the packet, then
  signals Token->Event when the IP layer completes.  We replicate this
  by populating Token->Status but NOT signaling Token->Event when the
  advance context is active.
**/
STATIC
EFI_STATUS
EFIAPI
MockUdp6Transmit (
  IN EFI_UDP6_PROTOCOL          *This,
  IN EFI_UDP6_COMPLETION_TOKEN  *Token
  )
{
  UINT8  FuzzStatus;

  DEBUG ((DEBUG_VERBOSE, "MockUdp6: Transmit (token=%p)\n", Token));

  //
  // Check order matches real edk2: configured state before token validation
  //
  if (!mMockUdp6Configured) {
    return EFI_NOT_STARTED;
  }

  if ((Token == NULL) || (Token->Event == NULL)) {
    return EFI_INVALID_PARAMETER;
  }

  mMockUdp6TransmitCount++;

  //
  // Use fuzz data to control transmit completion status.
  //   Byte value 0   → EFI_SUCCESS  (common case)
  //   Byte value 1   → EFI_NETWORK_UNREACHABLE
  //   Byte value 2   → EFI_TIMEOUT
  //   Byte value 3   → EFI_ABORTED
  //   Anything else   → EFI_SUCCESS
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
  // Transmit completion is immediate — no data to defer.
  //
  MockDeferredSchedule (&mDeferredState, Token->Event);

  return EFI_SUCCESS;
}

/**
  Mock Receive - builds an EFI_UDP6_RECEIVE_DATA from fuzz bytes and
  populates the completion token.  Defers event signaling to direct signaling.

  Real edk2 Udp6Receive queues the token in Instance->RxTokens and
  returns immediately.  A network packet arriving later triggers
  Ip6DemultiplexDgram → Udp6Demultiplex → UdpIoOnDgramRcvd → DPC.
  We replicate this by building data now but deferring the event signal.
**/
STATIC
EFI_STATUS
EFIAPI
MockUdp6Receive (
  IN EFI_UDP6_PROTOCOL          *This,
  IN EFI_UDP6_COMPLETION_TOKEN  *Token
  )
{
  EFI_UDP6_RECEIVE_DATA    *RxData;
  UINT8                    *PayloadBuf;
  UINTN                     PayloadSize;
  UINTN                     Consumed;

  DEBUG ((DEBUG_VERBOSE, "MockUdp6: Receive (token=%p)\n", Token));

  //
  // Check order matches real edk2: configured state before token validation
  //
  if (!mMockUdp6Configured) {
    return EFI_NOT_STARTED;
  }

  if ((Token == NULL) || (Token->Event == NULL)) {
    return EFI_INVALID_PARAMETER;
  }

  mMockUdp6ReceiveCount++;

  //
  // 1. Consume 2-byte payload length hint from fuzz data.
  //
  {
    UINT8  LenHint[2] = { 0 };
    ConsumeFuzzBytes (LenHint, sizeof (LenHint), &Consumed);
    if (Consumed == 0) {
      //
      // Fuzz buffer exhausted — arm the token with ABORTED status.
      //
      DEBUG ((DEBUG_VERBOSE, "MockUdp6: Receive — fuzz exhausted, aborting\n"));
      Token->Packet.RxData = NULL;
      Token->Status        = EFI_ABORTED;
      MockDeferredSchedule (&mDeferredState, Token->Event);
      return EFI_SUCCESS;
    }

    PayloadSize = (UINTN)LenHint[0] | ((UINTN)LenHint[1] << 8);
    if (PayloadSize > 1452) {
      PayloadSize = 1452;  // Max UDP6 payload: 1500 MTU - 40 IPv6 - 8 UDP
    }
  }

  //
  // 2. Allocate RxData + trailing payload in a single pool block.
  //
  RxData = AllocateZeroPool (sizeof (EFI_UDP6_RECEIVE_DATA) + PayloadSize);
  if (RxData == NULL) {
    Token->Packet.RxData = NULL;
    Token->Status        = EFI_OUT_OF_RESOURCES;
    MockDeferredSchedule (&mDeferredState, Token->Event);
    return EFI_SUCCESS;
  }

  PayloadBuf = (UINT8 *)RxData + sizeof (EFI_UDP6_RECEIVE_DATA);

  //
  // 3. Fill payload from fuzz data.
  //
  ConsumeFuzzBytes (PayloadBuf, PayloadSize, &Consumed);
  if (Consumed < PayloadSize) {
    PayloadSize = Consumed;
  }

  //
  // 4. Populate RxData fields (matches real edk2 Udp6WrapRxData layout).
  //
  RxData->DataLength                      = (UINT32)PayloadSize;
  RxData->FragmentCount                   = 1;
  RxData->FragmentTable[0].FragmentLength = (UINT32)PayloadSize;
  RxData->FragmentTable[0].FragmentBuffer = PayloadBuf;

  //
  // Session data: source and destination addresses/ports.
  //
  CopyMem (&RxData->UdpSession.SourceAddress, &mDefaultSourceAddress, sizeof (EFI_IPv6_ADDRESS));
  RxData->UdpSession.SourcePort = 547;  // DHCPv6 server port

  if (mMockUdp6Configured) {
    CopyMem (
      &RxData->UdpSession.DestinationAddress,
      &mMockUdp6Config.StationAddress,
      sizeof (EFI_IPv6_ADDRESS)
      );
    RxData->UdpSession.DestinationPort = mMockUdp6Config.StationPort;
  }

  //
  // AUDIT-FIX: Create a bare RecycleSignal event.  The real edk2 Udp6Dxe
  // wraps received data and creates a recycle event whose callback frees
  // the wrapper.  Setting NULL would crash any consumer that calls
  // gBS->SignalEvent(RxData->RecycleSignal).
  //
  {
    EFI_EVENT  RecycleEvent = NULL;
    gBS->CreateEvent (0, TPL_CALLBACK, NULL, NULL, &RecycleEvent);
    RxData->RecycleSignal = RecycleEvent;
  }

  //
  // 5. Populate completion token — data is now ready for the consumer.
  //
  Token->Packet.RxData = RxData;
  Token->Status        = EFI_SUCCESS;

  //
  // Defer the token event signal to the next AdvanceTime tick.
  //
  MockDeferredSchedule (&mDeferredState, Token->Event);

  return EFI_SUCCESS;
}

/**
  Mock Cancel - cancel pending Transmit/Receive tokens.

  Real edk2 Udp6Cancel removes the token from Instance->TxTokens or
  Instance->RxTokens and signals it with EFI_ABORTED.

  @param[in]  This   Protocol instance pointer.
  @param[in]  Token  Token to cancel, or NULL to cancel all pending.

  @retval EFI_SUCCESS      Token(s) cancelled.
  @retval EFI_NOT_STARTED  Not configured.
  @retval EFI_NOT_FOUND    Specific token not in pending list.
**/
STATIC
EFI_STATUS
EFIAPI
MockUdp6Cancel (
  IN EFI_UDP6_PROTOCOL          *This,
  IN EFI_UDP6_COMPLETION_TOKEN  *Token  OPTIONAL
  )
{
  DEBUG ((DEBUG_VERBOSE, "MockUdp6: Cancel (token=%p)\n", Token));

  if (!mMockUdp6Configured) {
    return EFI_NOT_STARTED;
  }

  if (Token == NULL) {
    MockDeferredCancelAll (&mDeferredState);
    return EFI_SUCCESS;
  }

  return MockDeferredCancel (&mDeferredState, Token->Event);
}

/**
  Mock Poll - no-op.
**/
STATIC
EFI_STATUS
EFIAPI
MockUdp6Poll (
  IN EFI_UDP6_PROTOCOL  *This
  )
{
  return EFI_SUCCESS;
}

//=============================================================================
// State Reset
//=============================================================================

/**
  Reset mock state between fuzz iterations.

  Clears config, pending-token tracking, and counters.
  Does NOT touch fuzz context (managed by FuzzContextLib).
  Does NOT call CancelAllPendingTokens — Reset is called between
  test iterations (AFL) and in test SetUp; pending tokens may reference
  stack memory from prior test functions that have already returned.
  Configure(NULL) handles live cancellation.
**/

STATIC
VOID
EFIAPI
ResetState (
  VOID
  )
{
  DEBUG ((DEBUG_VERBOSE, "MockUdp6: ResetState\n"));
  ZeroMem (&mMockUdp6Config, sizeof (mMockUdp6Config));
  mMockUdp6Configured    = FALSE;
  mMockUdp6TransmitCount = 0;
  mMockUdp6ReceiveCount  = 0;

  MockDeferredReset (&mDeferredState);
}

//=============================================================================
// Library Constructor
//=============================================================================

/**
  Initialize mock UDP6 protocol and install on gFuzzHandle.

  @retval RETURN_SUCCESS  Always succeeds.
**/
RETURN_STATUS
EFIAPI
MockgEfiUdp6ProtocolGuidConstructor (
  VOID
  )
{
  EFI_STATUS  Status;

  DEBUG ((DEBUG_INFO, "MockgEfiUdp6ProtocolGuid: Constructor\n"));

  //
  // Wire up all 7 function pointers
  //
  mMockUdp6Protocol.GetModeData = MockUdp6GetModeData;
  mMockUdp6Protocol.Configure   = MockUdp6Configure;
  mMockUdp6Protocol.Groups      = MockUdp6Groups;
  mMockUdp6Protocol.Transmit    = MockUdp6Transmit;
  mMockUdp6Protocol.Receive     = MockUdp6Receive;
  mMockUdp6Protocol.Cancel      = MockUdp6Cancel;
  mMockUdp6Protocol.Poll        = MockUdp6Poll;

  ResetState ();
  MockProtocolRegisterReset (ResetState);

  if ((gBS == NULL) || (gFuzzHandle == NULL)) {
    DEBUG ((DEBUG_WARN, "MockgEfiUdp6ProtocolGuid: gBS or gFuzzHandle NULL — skipping install\n"));
    return RETURN_SUCCESS;
  }

  Status = gBS->InstallProtocolInterface (
                  &gFuzzHandle,
                  &gEfiUdp6ProtocolGuid,
                  EFI_NATIVE_INTERFACE,
                  &mMockUdp6Protocol
                  );
  DEBUG ((DEBUG_INFO, "MockgEfiUdp6ProtocolGuid: InstallProtocolInterface on gFuzzHandle: %r\n", Status));
  if (EFI_ERROR (Status)) {
    return RETURN_DEVICE_ERROR;
  }

  DEBUG ((DEBUG_INFO, "MockgEfiUdp6ProtocolGuid: Constructor complete\n"));
  return RETURN_SUCCESS;
}
