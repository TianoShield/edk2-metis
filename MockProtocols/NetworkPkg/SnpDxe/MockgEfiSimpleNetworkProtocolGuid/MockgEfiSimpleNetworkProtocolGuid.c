/** @file MockgEfiSimpleNetworkProtocolGuid.c
    HBFAplus Mock Simple Network Protocol Implementation (self-contained).

    Mock EFI_SIMPLE_NETWORK_PROTOCOL for fuzzing drivers that consume SNP
    (MnpDxe, ArpDxe, Ip4Dxe, Ip6Dxe, Dhcp4Dxe, Dhcp6Dxe, etc.).

    Behaviour:
      - Start/Stop/Initialize/Shutdown/Reset: genuine state machine
        (Stopped <-> Started <-> Initialized) matching UEFI spec §24.1
      - ReceiveFilters: stores filter mask, returns SUCCESS
      - StationAddress: stores address, returns SUCCESS
      - Statistics: returns zeroed stats, supports reset
      - MCastIpToMac: deterministic multicast MAC derivation per RFC
      - NvData: no-op SUCCESS
      - GetStatus: returns fuzz-driven interrupt status + recycle TX buf
      - Transmit: accepts packet, records buffer for GetStatus recycling
      - Receive: returns fuzz-data-driven packet

    Mode defaults (Ethernet-like):
      - HwAddressSize = 6, MediaHeaderSize = 14, MaxPacketSize = 1500
      - IfType = 1 (Ethernet), MediaPresent = TRUE
      - PermanentAddress = 02:00:00:00:00:01

    Copyright (c) 2025-2026, HBFAplus Contributors. All rights reserved.
    SPDX-License-Identifier: BSD-2-Clause-Patent
**/

//=============================================================================
// UEFI Spec Audit — §24.1 (EFI Simple Network Protocol)
//
// Real UEFI: SNP provides a packet-level interface to a network adapter.
//   The adapter goes through Stopped -> Started -> Initialized states.
//   Mode struct exposes HW capabilities (MAC, packet size, etc.).
//
// Our mock: Self-contained with fuzz-byte-driven Receive/GetStatus.
//   State machine is faithfully implemented. Mode populated with
//   realistic Ethernet-like values so consumers (MnpDxe, etc.) work.
//
// Deviations:
//   1. No real NIC — Transmit accepts data but discards it.
//   2. Receive returns fuzz-driven data instead of wire packets.
//   3. Statistics are zeroed (no real counters).
//   4. NvData is no-op (no NVRAM attached).
//   5. WaitForPacket event is created but never signaled by HW.
//=============================================================================

#include <Uefi.h>
#include <Library/BaseLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/DebugLib.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Protocol/SimpleNetwork.h>
#include <Library/FuzzContextLib.h>

//=============================================================================
// Module-scope state
//=============================================================================

STATIC EFI_SIMPLE_NETWORK_PROTOCOL  mMockSnpProtocol;
STATIC EFI_SIMPLE_NETWORK_MODE      mMockSnpMode;
STATIC EFI_NETWORK_STATISTICS       mMockSnpStatistics;

//
// Last transmitted buffer address for GetStatus TxBuf recycling.
//
STATIC VOID  *mLastTxBuf       = NULL;
STATIC BOOLEAN mTxBufRecycled  = TRUE;

extern EFI_HANDLE gFuzzHandle;

//=============================================================================
// Internal helpers
//=============================================================================

/**
  Resolve the effective fuzz context for this protocol.
**/
STATIC
MOCK_FUZZ_CONTEXT *
ResolveContext (
  VOID
  )
{
  MOCK_FUZZ_CONTEXT  *Override;

  Override = MockFuzzContextGetProtocolContext (&gEfiSimpleNetworkProtocolGuid);
  return (Override != NULL) ? Override : MockFuzzContextGetPool ();
}

/**
  Consume fuzz bytes with fallback to zero-fill.
**/
STATIC
VOID
ConsumeFuzzBytes (
  OUT UINT8  *Buffer,
  IN  UINTN   RequestedSize,
  OUT UINTN  *ActualSize
  )
{
  MOCK_FUZZ_CONTEXT  *Ctx;
  UINT8              *Src;
  UINTN               Available;

  Ctx = ResolveContext ();
  if ((Ctx == NULL) || (Ctx->Buffer == NULL) || (Ctx->Size == 0)) {
    ZeroMem (Buffer, RequestedSize);
    *ActualSize = 0;
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

/**
  Initialize Mode with Ethernet-like defaults.
**/
STATIC
VOID
InitModeDefaults (
  VOID
  )
{
  ZeroMem (&mMockSnpMode, sizeof (mMockSnpMode));

  mMockSnpMode.State                 = EfiSimpleNetworkStopped;
  mMockSnpMode.HwAddressSize         = 6;
  mMockSnpMode.MediaHeaderSize       = 14;
  mMockSnpMode.MaxPacketSize         = 1500;
  mMockSnpMode.NvRamSize             = 0;
  mMockSnpMode.NvRamAccessSize       = 0;
  mMockSnpMode.ReceiveFilterMask     = EFI_SIMPLE_NETWORK_RECEIVE_UNICAST
                                     | EFI_SIMPLE_NETWORK_RECEIVE_MULTICAST
                                     | EFI_SIMPLE_NETWORK_RECEIVE_BROADCAST
                                     | EFI_SIMPLE_NETWORK_RECEIVE_PROMISCUOUS
                                     | EFI_SIMPLE_NETWORK_RECEIVE_PROMISCUOUS_MULTICAST;
  mMockSnpMode.ReceiveFilterSetting  = EFI_SIMPLE_NETWORK_RECEIVE_UNICAST
                                     | EFI_SIMPLE_NETWORK_RECEIVE_BROADCAST;
  mMockSnpMode.MaxMCastFilterCount   = MAX_MCAST_FILTER_CNT;
  mMockSnpMode.MCastFilterCount      = 0;
  mMockSnpMode.IfType                = 1;  // Ethernet
  mMockSnpMode.MacAddressChangeable  = TRUE;
  mMockSnpMode.MultipleTxSupported   = TRUE;
  mMockSnpMode.MediaPresentSupported = TRUE;
  mMockSnpMode.MediaPresent          = TRUE;

  //
  // Permanent address: locally-administered unicast MAC 02:00:00:00:00:01
  //
  ZeroMem (&mMockSnpMode.PermanentAddress, sizeof (EFI_MAC_ADDRESS));
  mMockSnpMode.PermanentAddress.Addr[0] = 0x02;
  mMockSnpMode.PermanentAddress.Addr[5] = 0x01;

  CopyMem (&mMockSnpMode.CurrentAddress, &mMockSnpMode.PermanentAddress,
           sizeof (EFI_MAC_ADDRESS));

  //
  // Broadcast address: FF:FF:FF:FF:FF:FF
  //
  SetMem (&mMockSnpMode.BroadcastAddress, 6, 0xFF);
}

//=============================================================================
// State-machine functions (Configuration)
//=============================================================================

STATIC
EFI_STATUS
EFIAPI
MockSnpStart (
  IN EFI_SIMPLE_NETWORK_PROTOCOL  *This
  )
{
  if (This == NULL) {
    return EFI_INVALID_PARAMETER;
  }

  if (mMockSnpMode.State == EfiSimpleNetworkStarted ||
      mMockSnpMode.State == EfiSimpleNetworkInitialized) {
    return EFI_ALREADY_STARTED;
  }

  if (mMockSnpMode.State != EfiSimpleNetworkStopped) {
    return EFI_DEVICE_ERROR;
  }

  mMockSnpMode.State = EfiSimpleNetworkStarted;
  DEBUG ((DEBUG_VERBOSE, "MockSnp: Start -> Started\n"));
  return EFI_SUCCESS;
}

STATIC
EFI_STATUS
EFIAPI
MockSnpStop (
  IN EFI_SIMPLE_NETWORK_PROTOCOL  *This
  )
{
  if (This == NULL) {
    return EFI_INVALID_PARAMETER;
  }

  if (mMockSnpMode.State == EfiSimpleNetworkStopped) {
    return EFI_NOT_STARTED;
  }

  mMockSnpMode.State = EfiSimpleNetworkStopped;
  DEBUG ((DEBUG_VERBOSE, "MockSnp: Stop -> Stopped\n"));
  return EFI_SUCCESS;
}

STATIC
EFI_STATUS
EFIAPI
MockSnpInitialize (
  IN EFI_SIMPLE_NETWORK_PROTOCOL  *This,
  IN UINTN                         ExtraRxBufferSize  OPTIONAL,
  IN UINTN                         ExtraTxBufferSize  OPTIONAL
  )
{
  if (This == NULL) {
    return EFI_INVALID_PARAMETER;
  }

  if (mMockSnpMode.State == EfiSimpleNetworkStopped) {
    return EFI_NOT_STARTED;
  }

  if (mMockSnpMode.State == EfiSimpleNetworkInitialized) {
    return EFI_SUCCESS; // already initialized
  }

  mMockSnpMode.State = EfiSimpleNetworkInitialized;
  mLastTxBuf     = NULL;
  mTxBufRecycled = TRUE;

  DEBUG ((DEBUG_VERBOSE, "MockSnp: Initialize -> Initialized\n"));
  return EFI_SUCCESS;
}

STATIC
EFI_STATUS
EFIAPI
MockSnpReset (
  IN EFI_SIMPLE_NETWORK_PROTOCOL  *This,
  IN BOOLEAN                       ExtendedVerification
  )
{
  if (This == NULL) {
    return EFI_INVALID_PARAMETER;
  }

  if (mMockSnpMode.State == EfiSimpleNetworkStopped) {
    return EFI_NOT_STARTED;
  }

  if (mMockSnpMode.State != EfiSimpleNetworkInitialized) {
    return EFI_DEVICE_ERROR;
  }

  // Reset stays in Initialized state (per UEFI spec)
  mLastTxBuf     = NULL;
  mTxBufRecycled = TRUE;
  ZeroMem (&mMockSnpStatistics, sizeof (mMockSnpStatistics));

  DEBUG ((DEBUG_VERBOSE, "MockSnp: Reset (Initialized)\n"));
  return EFI_SUCCESS;
}

STATIC
EFI_STATUS
EFIAPI
MockSnpShutdown (
  IN EFI_SIMPLE_NETWORK_PROTOCOL  *This
  )
{
  if (This == NULL) {
    return EFI_INVALID_PARAMETER;
  }

  if (mMockSnpMode.State == EfiSimpleNetworkStopped) {
    return EFI_NOT_STARTED;
  }

  if (mMockSnpMode.State != EfiSimpleNetworkInitialized) {
    return EFI_DEVICE_ERROR;
  }

  mMockSnpMode.State = EfiSimpleNetworkStarted;
  mLastTxBuf     = NULL;
  mTxBufRecycled = TRUE;
  ZeroMem (&mMockSnpStatistics, sizeof (mMockSnpStatistics));

  DEBUG ((DEBUG_VERBOSE, "MockSnp: Shutdown -> Started\n"));
  return EFI_SUCCESS;
}

//=============================================================================
// Configuration functions
//=============================================================================

STATIC
EFI_STATUS
EFIAPI
MockSnpReceiveFilters (
  IN EFI_SIMPLE_NETWORK_PROTOCOL  *This,
  IN UINT32                        Enable,
  IN UINT32                        Disable,
  IN BOOLEAN                       ResetMCastFilter,
  IN UINTN                         MCastFilterCnt  OPTIONAL,
  IN EFI_MAC_ADDRESS              *MCastFilter     OPTIONAL
  )
{
  if (This == NULL) {
    return EFI_INVALID_PARAMETER;
  }

  if (mMockSnpMode.State == EfiSimpleNetworkStopped) {
    return EFI_NOT_STARTED;
  }

  if (mMockSnpMode.State != EfiSimpleNetworkInitialized) {
    return EFI_DEVICE_ERROR;
  }

  mMockSnpMode.ReceiveFilterSetting |= Enable;
  mMockSnpMode.ReceiveFilterSetting &= ~Disable;

  if (ResetMCastFilter) {
    mMockSnpMode.MCastFilterCount = 0;
    ZeroMem (mMockSnpMode.MCastFilter, sizeof (mMockSnpMode.MCastFilter));
  } else if ((MCastFilter != NULL) && (MCastFilterCnt > 0)) {
    if (MCastFilterCnt > MAX_MCAST_FILTER_CNT) {
      MCastFilterCnt = MAX_MCAST_FILTER_CNT;
    }

    mMockSnpMode.MCastFilterCount = (UINT32)MCastFilterCnt;
    CopyMem (mMockSnpMode.MCastFilter, MCastFilter,
             MCastFilterCnt * sizeof (EFI_MAC_ADDRESS));
  }

  return EFI_SUCCESS;
}

STATIC
EFI_STATUS
EFIAPI
MockSnpStationAddress (
  IN EFI_SIMPLE_NETWORK_PROTOCOL  *This,
  IN BOOLEAN                       Reset,
  IN EFI_MAC_ADDRESS              *New  OPTIONAL
  )
{
  if (This == NULL) {
    return EFI_INVALID_PARAMETER;
  }

  if (mMockSnpMode.State == EfiSimpleNetworkStopped) {
    return EFI_NOT_STARTED;
  }

  if (mMockSnpMode.State != EfiSimpleNetworkInitialized) {
    return EFI_DEVICE_ERROR;
  }

  if (Reset) {
    CopyMem (&mMockSnpMode.CurrentAddress, &mMockSnpMode.PermanentAddress,
             sizeof (EFI_MAC_ADDRESS));
  } else if (New != NULL) {
    CopyMem (&mMockSnpMode.CurrentAddress, New, sizeof (EFI_MAC_ADDRESS));
  } else {
    return EFI_INVALID_PARAMETER;
  }

  return EFI_SUCCESS;
}

//=============================================================================
// State query functions
//=============================================================================

STATIC
EFI_STATUS
EFIAPI
MockSnpStatistics (
  IN EFI_SIMPLE_NETWORK_PROTOCOL  *This,
  IN BOOLEAN                       Reset,
  IN OUT UINTN                    *StatisticsSize  OPTIONAL,
  OUT EFI_NETWORK_STATISTICS      *StatisticsTable OPTIONAL
  )
{
  if (This == NULL) {
    return EFI_INVALID_PARAMETER;
  }

  if (mMockSnpMode.State == EfiSimpleNetworkStopped) {
    return EFI_NOT_STARTED;
  }

  if (mMockSnpMode.State != EfiSimpleNetworkInitialized) {
    return EFI_DEVICE_ERROR;
  }

  if (Reset) {
    ZeroMem (&mMockSnpStatistics, sizeof (mMockSnpStatistics));
  }

  if (StatisticsTable != NULL) {
    if (StatisticsSize == NULL) {
      return EFI_INVALID_PARAMETER;
    }

    if (*StatisticsSize < sizeof (EFI_NETWORK_STATISTICS)) {
      *StatisticsSize = sizeof (EFI_NETWORK_STATISTICS);
      return EFI_BUFFER_TOO_SMALL;
    }

    CopyMem (StatisticsTable, &mMockSnpStatistics,
             sizeof (EFI_NETWORK_STATISTICS));
    *StatisticsSize = sizeof (EFI_NETWORK_STATISTICS);
  }

  return EFI_SUCCESS;
}

STATIC
EFI_STATUS
EFIAPI
MockSnpMCastIpToMac (
  IN EFI_SIMPLE_NETWORK_PROTOCOL  *This,
  IN BOOLEAN                       IPv6,
  IN EFI_IP_ADDRESS               *IP,
  OUT EFI_MAC_ADDRESS             *MAC
  )
{
  if (This == NULL || IP == NULL || MAC == NULL) {
    return EFI_INVALID_PARAMETER;
  }

  if (mMockSnpMode.State == EfiSimpleNetworkStopped) {
    return EFI_NOT_STARTED;
  }

  if (mMockSnpMode.State != EfiSimpleNetworkInitialized) {
    return EFI_DEVICE_ERROR;
  }

  ZeroMem (MAC, sizeof (EFI_MAC_ADDRESS));

  if (IPv6) {
    //
    // RFC 2464: IPv6 multicast MAC = 33:33:xx:xx:xx:xx
    // (last 4 bytes of IPv6 address)
    //
    MAC->Addr[0] = 0x33;
    MAC->Addr[1] = 0x33;
    MAC->Addr[2] = IP->v6.Addr[12];
    MAC->Addr[3] = IP->v6.Addr[13];
    MAC->Addr[4] = IP->v6.Addr[14];
    MAC->Addr[5] = IP->v6.Addr[15];
  } else {
    //
    // RFC 1112: IPv4 multicast MAC = 01:00:5E:xx:xx:xx
    // (low 23 bits of IPv4 address)
    //
    MAC->Addr[0] = 0x01;
    MAC->Addr[1] = 0x00;
    MAC->Addr[2] = 0x5E;
    MAC->Addr[3] = IP->v4.Addr[1] & 0x7F;
    MAC->Addr[4] = IP->v4.Addr[2];
    MAC->Addr[5] = IP->v4.Addr[3];
  }

  return EFI_SUCCESS;
}

STATIC
EFI_STATUS
EFIAPI
MockSnpNvData (
  IN EFI_SIMPLE_NETWORK_PROTOCOL  *This,
  IN BOOLEAN                       ReadWrite,
  IN UINTN                         Offset,
  IN UINTN                         BufferSize,
  IN OUT VOID                     *Buffer
  )
{
  if (This == NULL || Buffer == NULL) {
    return EFI_INVALID_PARAMETER;
  }

  if (mMockSnpMode.State == EfiSimpleNetworkStopped) {
    return EFI_NOT_STARTED;
  }

  // No-op — no NVRAM attached
  return EFI_UNSUPPORTED;
}

//=============================================================================
// GetStatus — state query + TX buffer recycle
//=============================================================================

STATIC
EFI_STATUS
EFIAPI
MockSnpGetStatus (
  IN EFI_SIMPLE_NETWORK_PROTOCOL  *This,
  OUT UINT32                      *InterruptStatus  OPTIONAL,
  OUT VOID                       **TxBuf            OPTIONAL
  )
{
  if (This == NULL) {
    return EFI_INVALID_PARAMETER;
  }

  if (mMockSnpMode.State == EfiSimpleNetworkStopped) {
    return EFI_NOT_STARTED;
  }

  if (mMockSnpMode.State != EfiSimpleNetworkInitialized) {
    return EFI_DEVICE_ERROR;
  }

  if (InterruptStatus != NULL) {
    *InterruptStatus = 0;
  }

  if (TxBuf != NULL) {
    if (!mTxBufRecycled && (mLastTxBuf != NULL)) {
      *TxBuf = mLastTxBuf;
      mTxBufRecycled = TRUE;
    } else {
      *TxBuf = NULL;
    }
  }

  return EFI_SUCCESS;
}

//=============================================================================
// Data transmit — accept packet, record TX buffer for recycling
//=============================================================================

STATIC
EFI_STATUS
EFIAPI
MockSnpTransmit (
  IN EFI_SIMPLE_NETWORK_PROTOCOL  *This,
  IN UINTN                         HeaderSize,
  IN UINTN                         BufferSize,
  IN VOID                         *Buffer,
  IN EFI_MAC_ADDRESS              *SrcAddr   OPTIONAL,
  IN EFI_MAC_ADDRESS              *DestAddr  OPTIONAL,
  IN UINT16                       *Protocol  OPTIONAL
  )
{
  if (This == NULL || Buffer == NULL) {
    return EFI_INVALID_PARAMETER;
  }

  if (mMockSnpMode.State == EfiSimpleNetworkStopped) {
    return EFI_NOT_STARTED;
  }

  if (mMockSnpMode.State != EfiSimpleNetworkInitialized) {
    return EFI_DEVICE_ERROR;
  }

  if (BufferSize == 0) {
    return EFI_INVALID_PARAMETER;
  }

  if ((HeaderSize != 0) && (HeaderSize != mMockSnpMode.MediaHeaderSize)) {
    return EFI_INVALID_PARAMETER;
  }

  if ((HeaderSize != 0) && (DestAddr == NULL)) {
    return EFI_INVALID_PARAMETER;
  }

  //
  // Record this buffer so GetStatus can recycle it.
  // (MnpDxe calls GetStatus to reclaim TX buffers.)
  //
  mLastTxBuf     = Buffer;
  mTxBufRecycled = FALSE;

  mMockSnpStatistics.TxTotalFrames++;
  mMockSnpStatistics.TxGoodFrames++;
  mMockSnpStatistics.TxTotalBytes += BufferSize;

  return EFI_SUCCESS;
}

//=============================================================================
// Data receive — fuzz-byte-driven packet return
//=============================================================================

STATIC
EFI_STATUS
EFIAPI
MockSnpReceive (
  IN EFI_SIMPLE_NETWORK_PROTOCOL  *This,
  OUT UINTN                       *HeaderSize  OPTIONAL,
  IN OUT UINTN                    *BufferSize,
  OUT VOID                        *Buffer,
  OUT EFI_MAC_ADDRESS             *SrcAddr     OPTIONAL,
  OUT EFI_MAC_ADDRESS             *DestAddr    OPTIONAL,
  OUT UINT16                      *Protocol    OPTIONAL
  )
{
  UINTN   Consumed;
  UINTN   PacketLen;
  UINT8   LenHint[2];

  if (This == NULL || BufferSize == NULL || Buffer == NULL) {
    return EFI_INVALID_PARAMETER;
  }

  if (mMockSnpMode.State == EfiSimpleNetworkStopped) {
    return EFI_NOT_STARTED;
  }

  if (mMockSnpMode.State != EfiSimpleNetworkInitialized) {
    return EFI_DEVICE_ERROR;
  }

  //
  // Consume 2-byte length hint from fuzz data
  //
  ConsumeFuzzBytes (LenHint, sizeof (LenHint), &Consumed);
  if (Consumed == 0) {
    return EFI_NOT_READY;
  }

  PacketLen = (UINTN)LenHint[0] | ((UINTN)LenHint[1] << 8);

  //
  // Clamp to reasonable Ethernet range (at least a header, at most MaxPacket)
  //
  if (PacketLen < mMockSnpMode.MediaHeaderSize) {
    PacketLen = mMockSnpMode.MediaHeaderSize;
  }

  if (PacketLen > mMockSnpMode.MaxPacketSize + mMockSnpMode.MediaHeaderSize) {
    PacketLen = mMockSnpMode.MaxPacketSize + mMockSnpMode.MediaHeaderSize;
  }

  if (*BufferSize < PacketLen) {
    *BufferSize = PacketLen;
    return EFI_BUFFER_TOO_SMALL;
  }

  //
  // Fill buffer with fuzz data
  //
  ConsumeFuzzBytes ((UINT8 *)Buffer, PacketLen, &Consumed);
  if (Consumed < PacketLen) {
    ZeroMem ((UINT8 *)Buffer + Consumed, PacketLen - Consumed);
  }

  *BufferSize = PacketLen;

  //
  // Extract header fields for out parameters
  //
  if (HeaderSize != NULL) {
    *HeaderSize = mMockSnpMode.MediaHeaderSize;
  }

  if ((DestAddr != NULL) && (PacketLen >= 6)) {
    ZeroMem (DestAddr, sizeof (EFI_MAC_ADDRESS));
    CopyMem (DestAddr, Buffer, 6);
  }

  if ((SrcAddr != NULL) && (PacketLen >= 12)) {
    ZeroMem (SrcAddr, sizeof (EFI_MAC_ADDRESS));
    CopyMem (SrcAddr, (UINT8 *)Buffer + 6, 6);
  }

  if ((Protocol != NULL) && (PacketLen >= 14)) {
    //
    // EtherType is at offset 12, big-endian 16-bit
    //
    *Protocol = (UINT16)(((UINT8 *)Buffer)[12] << 8 | ((UINT8 *)Buffer)[13]);
  }

  mMockSnpStatistics.RxTotalFrames++;
  mMockSnpStatistics.RxGoodFrames++;
  mMockSnpStatistics.RxTotalBytes += PacketLen;

  return EFI_SUCCESS;
}

//=============================================================================
// ResetState — inter-iteration cleanup
//=============================================================================

STATIC
VOID
EFIAPI
ResetState (
  VOID
  )
{
  DEBUG ((DEBUG_VERBOSE, "MockSnp: ResetState\n"));
  InitModeDefaults ();
  ZeroMem (&mMockSnpStatistics, sizeof (mMockSnpStatistics));
  mLastTxBuf     = NULL;
  mTxBufRecycled = TRUE;
}

//=============================================================================
// Constructor
//=============================================================================

RETURN_STATUS
EFIAPI
MockgEfiSimpleNetworkProtocolGuidConstructor (
  VOID
  )
{
  EFI_STATUS  Status;

  DEBUG ((DEBUG_INFO, "MockgEfiSimpleNetworkProtocolGuid: Constructor\n"));

  //
  // Initialize Mode with Ethernet-like defaults
  //
  InitModeDefaults ();
  ZeroMem (&mMockSnpStatistics, sizeof (mMockSnpStatistics));

  //
  // Wire all function pointers
  //
  mMockSnpProtocol.Revision       = EFI_SIMPLE_NETWORK_PROTOCOL_REVISION;
  mMockSnpProtocol.Start          = MockSnpStart;
  mMockSnpProtocol.Stop           = MockSnpStop;
  mMockSnpProtocol.Initialize     = MockSnpInitialize;
  mMockSnpProtocol.Reset          = MockSnpReset;
  mMockSnpProtocol.Shutdown       = MockSnpShutdown;
  mMockSnpProtocol.ReceiveFilters = MockSnpReceiveFilters;
  mMockSnpProtocol.StationAddress = MockSnpStationAddress;
  mMockSnpProtocol.Statistics     = MockSnpStatistics;
  mMockSnpProtocol.MCastIpToMac   = MockSnpMCastIpToMac;
  mMockSnpProtocol.NvData         = MockSnpNvData;
  mMockSnpProtocol.GetStatus      = MockSnpGetStatus;
  mMockSnpProtocol.Transmit       = MockSnpTransmit;
  mMockSnpProtocol.Receive        = MockSnpReceive;
  mMockSnpProtocol.WaitForPacket  = NULL;   // No HW event in mock
  mMockSnpProtocol.Mode           = &mMockSnpMode;

  //
  // Register inter-iteration reset
  //
  ResetState ();
  MockProtocolRegisterReset (ResetState);

  if ((gBS == NULL) || (gFuzzHandle == NULL)) {
    DEBUG ((DEBUG_WARN, "MockgEfiSimpleNetworkProtocolGuid: gBS or gFuzzHandle NULL\n"));
    return RETURN_SUCCESS;
  }

  //
  // Install on gFuzzHandle
  //
  Status = gBS->InstallProtocolInterface (
                  &gFuzzHandle,
                  &gEfiSimpleNetworkProtocolGuid,
                  EFI_NATIVE_INTERFACE,
                  &mMockSnpProtocol
                  );
  DEBUG ((DEBUG_INFO, "MockgEfiSimpleNetworkProtocolGuid: Install %r\n", Status));

  return EFI_ERROR (Status) ? RETURN_DEVICE_ERROR : RETURN_SUCCESS;
}
