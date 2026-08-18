/** @file TestDhcp6Driver.c
//
// HARNESS_PROTOCOLS: EFI_DHCP6_PROTOCOL, EFI_SERVICE_BINDING_PROTOCOL
//
    Fuzz harness for Dhcp6Dxe — exercises every entry point of both
    gEfiDhcp6ProtocolGuid and gEfiDhcp6ServiceBindingProtocolGuid.

    ===========================================================================
    Design Philosophy
    ===========================================================================

    Unlike the old per-function harnesses that manually constructed
    DHCP6_INSTANCE/DHCP6_SERVICE structs, this harness drives the real driver
    initialization path:

      Dhcp6DriverEntryPoint()       →  installs DriverBinding on ImageHandle
      DriverBinding->Supported()    →  checks gEfiUdp6ServiceBindingProtocolGuid
      DriverBinding->Start()        →  Dhcp6CreateService (finds SNP, Ip6Config,
                                       RNG, creates UdpIo via ServiceBinding)
      ServiceBinding->CreateChild() →  creates DHCP6_INSTANCE, installs Dhcp6Protocol

    All mock protocols are pre-installed on gFuzzHandle by their constructors
    (SNP, Ip6Config, RNG, UDP6, UDP6 ServiceBinding).  The driver code
    discovers them via standard gBS->OpenProtocol/HandleProtocol/LocateProtocol.

    ===========================================================================
    Per-Protocol Sub-Context Design  (Protocol Context Registry)
    ===========================================================================

    This harness uses the FuzzContextLib sub-context and protocol context
    registry features to give the fuzzer independent control over:
      (a) UDP6 network response bytes (Transmit statuses, Receive payloads)
      (b) API parameter bytes (config structs, packet data)

    Without sub-contexts, ALL consumers read from a single shared offset.
    Mutating one byte shifts every subsequent consumer — making it hard for
    the fuzzer to independently explore protocol responses vs API parameters.

    With sub-contexts, RunTestHarness carves a dedicated byte region for
    UDP6 and registers it via MockFuzzContextSetProtocolContext().  The
    UDP6 mock's ResolveContext() finds the override and consumes from it
    instead of the shared pool.  This separation lets the fuzzer:
      - Vary network conditions (TX failures, RX payloads) independently
      - Keep API parameter bytes stable while exploring network paths
      - Target specific UDP6 byte patterns without disturbing harness logic

    ===========================================================================
    Fuzz Input Layout  (after ToolChainHarnessLib skips bootstrap region)
    ===========================================================================

      ┌──────────────────────────────────────────────────────────────────────┐
      │ Bootstrap Region (6 bytes — consumed during InitializeHarness)      │
      │   [0..3] MockRng::GetRNG(4)      — PseudoRandomU32 for XID         │
      │   [4..5] MockUdp6::Receive LE16  — length hint during UdpIoCreate  │
      │ (Handled by ToolChainHarnessLib; NOT visible to RunTestHarness)     │
      ├──────────────────────────────────────────────────────────────────────┤
      │ Harness Payload (starts at offset 6, all offsets below are relative)│
      │                                                                     │
      │   Byte 0:    API selector  (GetU8, mod API_COUNT)                   │
      │     0  = GetModeData         8  = RenewRebind                       │
      │     1  = Configure           9  = Decline                           │
      │     2  = ConfigureAndGet    10  = Release                           │
      │     3  = Parse              11  = SbCreateDestroy                   │
      │     4  = ConfigureAndStop   12  = ConfigureNull                     │
      │     5  = GetModeNullOnly    13  = StartUnconfigured                 │
      │     6  = Start              14  = FullLifecycle                     │
      │     7  = InfoRequest        15  = DriverStop (terminal)              │
      │                                                                     │
      │   Byte 1:    Sub-options    (GetU8, API-specific bitmask)           │
      │                                                                     │
      │   Byte 2-3:  UDP6 Budget    (GetU16 LE, capped at 4096)            │
      │              Number of bytes reserved for the UDP6 sub-context.     │
      │              Covers ALL runtime UDP6 Transmit + Receive calls.      │
      │              Set to 0 for APIs that don't use UDP6 (e.g. Parse).    │
      │                                                                     │
      │   Byte 4 .. 4+Budget-1:  UDP6 sub-context bytes                    │
      │              Carved via MockFuzzContextCreateSubContext() and        │
      │              registered with gEfiUdp6ProtocolGuid.  MockUdp6's      │
      │              ResolveContext() finds this override automatically.     │
      │              TX: 1 byte/call (status selector)                      │
      │              RX: 2 bytes LE16 length + payload                      │
      │                                                                     │
      │   Byte 4+Budget .. end-2:  API payload                             │
      │              Config structs, packet data, addresses — consumed by   │
      │              the selected Fuzz* handler function.                   │
      │                                                                     │
      │   Last 2 bytes: EventPump   (GetU16 LE bitmask)                    │
      │              Controls which timer/completion callbacks fire.         │
      └──────────────────────────────────────────────────────────────────────┘

    ===========================================================================
    Mock Protocol Dependencies
    ===========================================================================

      - MockgEfiRngProtocolGuid            (gBS->LocateProtocol by PseudoRandomU32)
      - MockgEfiSimpleNetworkProtocolGuid  (gBS->HandleProtocol by NetLibGetSnpHandle)
      - MockgEfiIp6ConfigProtocolGuid      (gBS->HandleProtocol by Dhcp6CreateService)
      - MockgEfiUdp6ServiceBindingProtocolGuid  (gBS->OpenProtocol by UdpIoCreateIo)
      - MockgEfiUdp6ProtocolGuid           (gBS->OpenProtocol by UdpIoCreateIo)

    ===========================================================================
    Protocol Context Registry Usage
    ===========================================================================

      For runtime UDP6 operations (Transmit/Receive), this harness registers
      a sub-context override so the MockUdp6 functions consume bytes from a
      dedicated region instead of the shared pool:

        MockFuzzContextCreateSubContext (FuzzCtx, &Udp6Sub, Udp6Budget);
        MockFuzzContextSetProtocolContext (&gEfiUdp6ProtocolGuid, &Udp6Sub);
        ... API handler runs, MockUdp6 uses Udp6Sub automatically ...
        MockFuzzContextClearProtocolContext (&gEfiUdp6ProtocolGuid);

      This pattern is recommended for any harness whose target driver
      consumes mock protocol bytes at runtime (not just during bootstrap).

    Copyright (c) 2025, HBFAplus Contributors. All rights reserved.
    SPDX-License-Identifier: BSD-2-Clause-Patent
**/

//=============================================================================
// Harness Audit — UEFI §29.4.2 (DHCP6)
//
// APIs: 9/9 (GetModeData, Configure, Start, InfoRequest, RenewRebind,
//       Decline, Release, Stop, Parse)
//       + ServiceBinding (CreateChild/DestroyChild)
//       + DriverBinding (Supported/Start/Stop)
// Access: Via protocol interface pointers (no internal function bypass)
// Lifecycle: EntryPoint → DriverBinding → ServiceBinding → Protocol API
// Deviations:
//   - Sub-context used for UDP6 network bytes (independent control)
//   - SARR exchange exercises deep state machine (Solicit→Advertise→
//     Request→Reply)
//   - Driver Stop is terminal (no restart) — mirrors real firmware
//     where DriverBinding happens once and the driver stays alive
// Coverage gaps:
//   - None — all 9 DHCP6 protocol APIs covered
//=============================================================================

#include <Uefi.h>
#include <Library/BaseLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/DebugLib.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Library/NetLib.h>
#include <Protocol/Dhcp6.h>
#include <Protocol/ServiceBinding.h>


//
// Shared fuzz context + mock registry
//
#include <Library/FuzzContextLib.h>
#include <Library/HostDispatcherLib.h>

//=============================================================================
// Extern declarations from Dhcp6Dxe (linked via NULL|Dhcp6Dxe.inf)
//=============================================================================

extern HOST_DRIVER_ENTRY  gHostDriverRegistry[];
extern EFI_HANDLE                   gFuzzHandle;




//=============================================================================
// Module state — set up once in InitializeHarness
//=============================================================================

STATIC EFI_DHCP6_PROTOCOL              *mDhcp6          = NULL;
STATIC EFI_HANDLE                       mChildHandle    = NULL;
STATIC EFI_SERVICE_BINDING_PROTOCOL    *mServiceBinding = NULL;

//=============================================================================
// Harness Configuration
//=============================================================================

#define MAX_FUZZ_INPUT_SIZE  (10 * 4096)  ///< 10 pages — enough for complex config + packet fuzzing

//
// API selector values (Byte 0 of fuzz input)
//
#define API_GET_MODE_DATA           0
#define API_CONFIGURE               1
#define API_CONFIGURE_AND_GET       2
#define API_PARSE                   3
#define API_CONFIGURE_AND_STOP      4
#define API_GET_MODE_NULL_ONLY      5
#define API_START                   6
#define API_INFO_REQUEST            7
#define API_RENEW_REBIND            8
#define API_DECLINE                 9
#define API_RELEASE                 10
#define API_SB_CREATE_DESTROY       11
#define API_CONFIGURE_NULL          12
#define API_START_UNCONFIGURED      13
#define API_FULL_LIFECYCLE          14
#define API_DRIVER_STOP              15
#define API_START_SARR              16
#define API_BOUND_OPS               17
#define API_COUNT                   18

//=============================================================================
// Helper: Build a minimal valid EFI_DHCP6_CONFIG_DATA from fuzz bytes
//=============================================================================

/**
  Construct a minimal EFI_DHCP6_CONFIG_DATA suitable for Dhcp6Configure().

  The retransmission parameters and IaDescriptor fields are filled from
  fuzz data.  The config must pass Dhcp6's validation checks:
    - IaDescriptor.Type must be IANA or IATA
    - Either IaInfoEvent or SolicitRetransmission must be non-NULL
    - If SolicitRetransmission != NULL, Mrc and Mrd can't both be 0

  @param[out]  Config  The config struct to populate (caller-owned stack/pool).
  @param[out]  Retrans Retransmission struct to populate (caller-owned).
  @param[in]   FuzzCtx Fuzz context to consume bytes from.
**/
STATIC
VOID
BuildFuzzConfig (
  OUT EFI_DHCP6_CONFIG_DATA    *Config,
  OUT EFI_DHCP6_RETRANSMISSION *Retrans,
  IN  MOCK_FUZZ_CONTEXT        *FuzzCtx
  )
{
  UINT8   TypeByte;
  UINT32  IaId;

  ZeroMem (Config, sizeof (*Config));
  ZeroMem (Retrans, sizeof (*Retrans));

  //
  // IaDescriptor.Type: map fuzz byte to a valid IA type so that
  // Configure succeeds for the deep-path functions.  The FuzzConfigure
  // API already has its own explicit invalid-type testing (bit 3 →
  // 0xFFFF), so we always supply a valid type here.
  //   EFI_DHCP6_IA_TYPE_NA = 3, EFI_DHCP6_IA_TYPE_TA = 4
  //
  TypeByte = MockFuzzContextGetU8 (FuzzCtx);
  Config->IaDescriptor.Type = (TypeByte & 1) ? EFI_DHCP6_IA_TYPE_TA
                                              : EFI_DHCP6_IA_TYPE_NA;

  //
  // IaDescriptor.IaId: consume 4 bytes
  //
  IaId = MockFuzzContextGetU32 (FuzzCtx);
  Config->IaDescriptor.IaId = IaId;

  //
  // SolicitRetransmission: must be non-NULL, with Mrc|Mrd != 0
  //
  Retrans->Irt = MockFuzzContextGetU32 (FuzzCtx);
  Retrans->Mrc = MockFuzzContextGetU32 (FuzzCtx);
  Retrans->Mrt = MockFuzzContextGetU32 (FuzzCtx);
  Retrans->Mrd = MockFuzzContextGetU32 (FuzzCtx);

  //
  // UEFI Spec: Mrc==0 && Mrd==0 is rejected by Configure.
  // Ensure at least one is non-zero so Configure succeeds for
  // deep-path harness functions.
  //
  if (Retrans->Mrc == 0 && Retrans->Mrd == 0) {
    Retrans->Mrd = 1;
  }

  Config->SolicitRetransmission = Retrans;

  //
  // Build fuzz-controlled OptionList — raw opcodes, let driver validate
  //
  {
    UINT8   RawCount;
    UINT32  OptIdx;

    RawCount = MockFuzzContextGetU8 (FuzzCtx);
    Config->OptionCount = (UINT32)(RawCount % 17);  // 0-16, OOM cap

    if (Config->OptionCount > 0) {
      Config->OptionList = AllocateZeroPool (
                             Config->OptionCount * sizeof (EFI_DHCP6_PACKET_OPTION *)
                             );
      if (Config->OptionList == NULL) {
        Config->OptionCount = 0;
      } else {
        for (OptIdx = 0; OptIdx < Config->OptionCount; OptIdx++) {
          UINT16  OpCode;
          UINT8   DataLen;
          UINTN   OptSize;

          OpCode  = MockFuzzContextGetU16 (FuzzCtx);
          DataLen = MockFuzzContextGetU8 (FuzzCtx);
          if (DataLen > 64) {
            DataLen = 64;  // Per-option OOM cap
          }

          OptSize = sizeof (EFI_DHCP6_PACKET_OPTION) + DataLen;
          Config->OptionList[OptIdx] = AllocateZeroPool (OptSize);
          if (Config->OptionList[OptIdx] == NULL) {
            Config->OptionCount = OptIdx;
            break;
          }

          Config->OptionList[OptIdx]->OpCode = OpCode;
          Config->OptionList[OptIdx]->OpLen  = HTONS (DataLen);

          if ((DataLen > 0) && (MockFuzzContextRemaining (FuzzCtx) > 0)) {
            UINTN  Avail = MockFuzzContextRemaining (FuzzCtx);
            UINTN  CLen  = (Avail < DataLen) ? Avail : (UINTN)DataLen;
            UINT8  *Src  = MockFuzzContextConsume (FuzzCtx, CLen);

            if (Src != NULL) {
              CopyMem (Config->OptionList[OptIdx]->Data, Src, CLen);
            }
          }
        }
      }
    } else {
      Config->OptionList = NULL;
    }
  }

  //
  // IaInfoEvent = NULL — we rely on SolicitRetransmission being non-NULL
  //
  Config->IaInfoEvent = NULL;
}

/**
  Free any OptionList memory allocated by BuildFuzzConfig().

  @param[in,out]  Config  The config whose OptionList to free.
**/
STATIC
VOID
CleanupFuzzConfig (
  IN OUT EFI_DHCP6_CONFIG_DATA  *Config
  )
{
  UINT32  Index;

  if (Config->OptionList != NULL) {
    for (Index = 0; Index < Config->OptionCount; Index++) {
      if (Config->OptionList[Index] != NULL) {
        FreePool (Config->OptionList[Index]);
      }
    }

    FreePool (Config->OptionList);
    Config->OptionList  = NULL;
    Config->OptionCount = 0;
  }
}

//=============================================================================
// Fuzz API exercisers
//=============================================================================

/**
  Exercise EfiDhcp6GetModeData with fuzz-controlled parameter combinations.

  Exercises all code paths in EfiDhcp6GetModeData:
  - NULL This pointer           -> EFI_INVALID_PARAMETER
  - Both output pointers NULL   -> EFI_INVALID_PARAMETER
  - Unconfigured + ConfigData   -> EFI_ACCESS_DENIED
  - Configured + valid pointers -> EFI_SUCCESS with deep-copied output

  GetModeData allocates new buffers for ClientId, Ia, and Ia->ReplyPacket
  that the caller is responsible for freeing.

  SubOptions byte (from fuzzer) controls parameter combinations:
    Bit 0 (0x01): ModeData output pointer non-NULL
    Bit 1 (0x02): ConfigData output pointer non-NULL
    Bit 2 (0x04): Pass NULL as 'This' pointer (INVALID_PARAMETER path)
    Bit 3 (0x08): Pre-configure instance before calling

  @param[in]  FuzzCtx     Fuzz context -- used to build config when bit 3 set.
  @param[in]  SubOptions  Bitmask controlling parameter combinations.
**/
STATIC
VOID
FuzzGetModeData (
  IN MOCK_FUZZ_CONTEXT  *FuzzCtx,
  IN UINT8               SubOptions
  )
{
  EFI_STATUS                Status;
  EFI_DHCP6_MODE_DATA       ModeData;
  EFI_DHCP6_CONFIG_DATA     CfgOut;
  EFI_DHCP6_MODE_DATA      *ModePtr;
  EFI_DHCP6_CONFIG_DATA    *CfgPtr;
  EFI_DHCP6_CONFIG_DATA     Config;
  EFI_DHCP6_RETRANSMISSION  Retrans;
  BOOLEAN                   DidConfigure;

  ZeroMem (&ModeData, sizeof (ModeData));
  ZeroMem (&CfgOut, sizeof (CfgOut));

  //
  // Bits 0-1: select which output pointers are non-NULL.
  // When both are 0, exercises the both-NULL INVALID_PARAMETER path.
  //
  ModePtr = (SubOptions & 0x01) ? &ModeData : NULL;
  CfgPtr  = (SubOptions & 0x02) ? &CfgOut   : NULL;

  //
  // Bit 3: optionally configure the instance first so GetModeData
  // returns real data (ClientId, IA descriptor, IA state).
  //
  DidConfigure = FALSE;
  if ((SubOptions & 0x08) && (FuzzCtx != NULL)) {
    BuildFuzzConfig (&Config, &Retrans, FuzzCtx);
    Status = mDhcp6->Configure (mDhcp6, &Config);
    if (!EFI_ERROR (Status)) {
      DidConfigure = TRUE;
    }

    CleanupFuzzConfig (&Config);
  }

  //
  // Bit 2: test NULL This -> INVALID_PARAMETER.
  // Otherwise call with valid This pointer.
  //
  if (SubOptions & 0x04) {
    mDhcp6->GetModeData (NULL, ModePtr, CfgPtr);
  } else {
    mDhcp6->GetModeData (mDhcp6, ModePtr, CfgPtr);
  }

  //
  // Free any deep-copied data returned by GetModeData.
  // GetModeData allocates: ClientId (DUID buffer), Ia (IA struct
  // with embedded IaAddress array), Ia->ReplyPacket.
  //
  if (ModePtr != NULL) {
    if (ModeData.ClientId != NULL) {
      FreePool (ModeData.ClientId);
    }
    if (ModeData.Ia != NULL) {
      if (ModeData.Ia->ReplyPacket != NULL) {
        FreePool (ModeData.Ia->ReplyPacket);
      }
      FreePool (ModeData.Ia);
    }
  }

  //
  // Cleanup: unconfigure if we configured above
  //
  if (DidConfigure) {
    mDhcp6->Configure (mDhcp6, NULL);
  }
}

/**
  Exercise EfiDhcp6Configure with fuzz-controlled configuration data.

  Exercises all code paths in EfiDhcp6Configure:
  - NULL This pointer                -> EFI_INVALID_PARAMETER
  - Valid config with fuzz IaDescriptor, retransmission, OptionList
  - Double-configure (already configured) -> EFI_ACCESS_DENIED
  - Invalid IA type                  -> EFI_INVALID_PARAMETER
  - Configure(NULL) unconfigure path -> cleanup / deregistration

  All configuration fields (IaDescriptor.Type, IaId, retransmission
  Irt/Mrc/Mrt/Mrd, OptionList option codes, lengths, and data) are
  derived from the fuzz buffer via BuildFuzzConfig().

  SubOptions byte controls edge-case behaviors:
    Bit 0 (0x01): Pass NULL as 'This' pointer (INVALID_PARAMETER)
    Bit 1 (0x02): Call GetModeData after successful configure
    Bit 2 (0x04): Attempt double-configure (ACCESS_DENIED path)
    Bit 3 (0x08): Force invalid IA type value 0xFFFF

  @param[in]  FuzzCtx     Fuzz context for config construction.
  @param[in]  SubOptions  Bitmask controlling edge-case behaviors.
**/
STATIC
VOID
FuzzConfigure (
  IN MOCK_FUZZ_CONTEXT  *FuzzCtx,
  IN UINT8               SubOptions
  )
{
  EFI_STATUS                Status;
  EFI_DHCP6_CONFIG_DATA     Config;
  EFI_DHCP6_RETRANSMISSION  Retrans;

  //
  // Bit 0: test NULL This -> INVALID_PARAMETER
  //
  if (SubOptions & 0x01) {
    BuildFuzzConfig (&Config, &Retrans, FuzzCtx);
    mDhcp6->Configure (NULL, &Config);
    CleanupFuzzConfig (&Config);
    return;
  }

  //
  // Build config from fuzz data -- IaDescriptor, retransmission,
  // and OptionList entries all come from the fuzzer.
  //
  BuildFuzzConfig (&Config, &Retrans, FuzzCtx);

  //
  // Bit 3: force invalid IA type to exercise type validation
  //
  if (SubOptions & 0x08) {
    Config.IaDescriptor.Type = 0xFFFF;
  }

  Status = mDhcp6->Configure (mDhcp6, &Config);
  DEBUG ((DEBUG_VERBOSE, "TestDhcp6Driver: Configure = %r\n", Status));

  //
  // Bit 2: attempt double-configure while already configured.
  // The driver should return EFI_ACCESS_DENIED.
  //
  if (!EFI_ERROR (Status) && (SubOptions & 0x04)) {
    EFI_DHCP6_CONFIG_DATA     Config2;
    EFI_DHCP6_RETRANSMISSION  Retrans2;

    BuildFuzzConfig (&Config2, &Retrans2, FuzzCtx);
    mDhcp6->Configure (mDhcp6, &Config2);
    CleanupFuzzConfig (&Config2);
  }

  //
  // Bit 1: read back config state via GetModeData.
  // Exercises the deep-copy path in GetModeData when instance
  // is configured (ClientId, IA descriptor, IA state).
  //
  if (!EFI_ERROR (Status) && (SubOptions & 0x02)) {
    FuzzGetModeData (FuzzCtx, 0x03);
  }

  //
  // Cleanup: unconfigure so next iteration starts clean
  //
  if (!EFI_ERROR (Status)) {
    mDhcp6->Configure (mDhcp6, NULL);
  }

  CleanupFuzzConfig (&Config);
}

/**
  Exercise EfiDhcp6Parse with a fuzz-controlled DHCPv6 packet.

  Parse() is a pure parser -- it walks option TLVs in the packet buffer
  and returns pointers into the packet.  This is the highest-value fuzz
  target for memory safety bugs (OOB reads in option iteration).

  Packet content, header, Size, and Length are all derived from the fuzz
  buffer.  The standard two-pass pattern (count options, then retrieve)
  matches real caller usage.

  SubOptions byte controls edge-case behaviors:
    Bit 0 (0x01): Pass NULL as 'This' pointer (INVALID_PARAMETER)
    Bit 1 (0x02): Pass NULL as 'Packet' pointer (INVALID_PARAMETER)
    Bit 2 (0x04): Pass NULL as 'OptionCount' pointer (INVALID_PARAMETER)
    Bit 3 (0x08): Fuzz Packet.Size independently from content length
    Bit 4 (0x10): Pre-fill OptionCount to exercise BUFFER_TOO_SMALL
    Bit 5 (0x20): Set Packet.Length > Packet.Size (inconsistent)

  @param[in]  FuzzCtx     Fuzz context for packet construction.
  @param[in]  SubOptions  Bitmask controlling edge-case parameters.
**/
STATIC
VOID
FuzzParse (
  IN MOCK_FUZZ_CONTEXT  *FuzzCtx,
  IN UINT8               SubOptions
  )
{
  EFI_DHCP6_PACKET         *Packet;
  EFI_DHCP6_PACKET_OPTION  **OptionList;
  UINT32                    OptionCount;
  UINTN                     PacketSize;
  UINTN                     DataLen;
  EFI_DHCP6_PROTOCOL       *ThisPtr;

  //
  // Bit 0: select This pointer -- NULL tests INVALID_PARAMETER
  //
  ThisPtr = (SubOptions & 0x01) ? NULL : mDhcp6;

  //
  // Bit 2: NULL OptionCount pointer -> INVALID_PARAMETER
  //
  if (SubOptions & 0x04) {
    EFI_DHCP6_PACKET  SmallPkt;
    ZeroMem (&SmallPkt, sizeof (SmallPkt));
    SmallPkt.Size   = sizeof (SmallPkt);
    SmallPkt.Length = sizeof (EFI_DHCP6_HEADER);
    mDhcp6->Parse (mDhcp6, &SmallPkt, NULL, NULL);
    return;
  }

  //
  // Bit 1: NULL Packet pointer -> INVALID_PARAMETER
  //
  if (SubOptions & 0x02) {
    OptionCount = 0;
    mDhcp6->Parse (mDhcp6, NULL, &OptionCount, NULL);
    return;
  }

  //
  // Build a DHCPv6 packet from fuzz data.
  // First 2 bytes = data length hint (capped at MAX_FUZZ_INPUT_SIZE).
  //
  DataLen = (UINTN)MockFuzzContextGetU16 (FuzzCtx);
  if (DataLen > MAX_FUZZ_INPUT_SIZE) {
    DataLen = MAX_FUZZ_INPUT_SIZE;
  }

  //
  // Bit 3: fuzz Packet.Size independently -- may be larger or smaller
  // than the actual content, testing Size/Length validation logic.
  //
  if (SubOptions & 0x08) {
    UINT16  FuzzSize = MockFuzzContextGetU16 (FuzzCtx);
    PacketSize = sizeof (EFI_DHCP6_PACKET) + (UINTN)FuzzSize;
    if (PacketSize < sizeof (EFI_DHCP6_PACKET)) {
      PacketSize = sizeof (EFI_DHCP6_PACKET);
    }
  } else {
    PacketSize = sizeof (EFI_DHCP6_PACKET) + DataLen;
  }

  Packet = AllocateZeroPool (PacketSize);
  if (Packet == NULL) {
    return;
  }

  Packet->Size = (UINT32)PacketSize;

  //
  // Bit 5: set Length > Size (inconsistent -- tests boundary validation)
  //
  if (SubOptions & 0x20) {
    Packet->Length = (UINT32)(PacketSize + MockFuzzContextGetU8 (FuzzCtx) + 1);
  } else {
    Packet->Length = (UINT32)(sizeof (EFI_DHCP6_HEADER) + DataLen);
    if (Packet->Length > Packet->Size) {
      Packet->Length = Packet->Size;
    }
  }

  //
  // Fill the DHCPv6 header + options area from fuzz data.
  // Dhcp6.Header contains MessageType (1 byte) and TransactionId (3 bytes).
  // The remaining bytes are the option TLV area.
  //
  if (MockFuzzContextRemaining (FuzzCtx) > 0) {
    UINTN  CopyLen   = DataLen + sizeof (EFI_DHCP6_HEADER);
    UINTN  MaxCopy   = PacketSize - OFFSET_OF (EFI_DHCP6_PACKET, Dhcp6);
    UINTN  Available = MockFuzzContextRemaining (FuzzCtx);

    if (CopyLen > MaxCopy) {
      CopyLen = MaxCopy;
    }
    if (Available < CopyLen) {
      CopyLen = Available;
    }

    {
      UINT8  *Src = MockFuzzContextConsume (FuzzCtx, CopyLen);
      if (Src != NULL) {
        CopyMem (&Packet->Dhcp6, Src, CopyLen);
      }
    }
  }

  //
  // Phase 1: get option count.
  // Bit 4: pre-fill OptionCount with a fuzz value to exercise the
  // EFI_BUFFER_TOO_SMALL path when OptionCount < actual count.
  //
  if (SubOptions & 0x10) {
    OptionCount = (UINT32)(MockFuzzContextGetU8 (FuzzCtx) % 4);
  } else {
    OptionCount = 0;
  }

  mDhcp6->Parse (ThisPtr, Packet, &OptionCount, NULL);

  //
  // Phase 2: retrieve option pointers with properly sized array.
  // Each returned pointer points into the Packet buffer -- no
  // separate allocation, so only the OptionList array is freed.
  //
  if (OptionCount > 0 && OptionCount <= 1024) {
    OptionList = AllocateZeroPool (OptionCount * sizeof (EFI_DHCP6_PACKET_OPTION *));
    if (OptionList != NULL) {
      mDhcp6->Parse (ThisPtr, Packet, &OptionCount, OptionList);
      FreePool (OptionList);
    }
  }

  FreePool (Packet);
}

/**
  Dummy event notification callback.

  Used as the NotifyFunction for EVT_NOTIFY_SIGNAL events (e.g.
  IaInfoEvent, TimeoutEvent).  UEFI Spec requires that notify-type
  events have a non-NULL callback; this no-op satisfies that contract
  while keeping fuzzing behaviour unchanged.
**/
STATIC
VOID
EFIAPI
DummyDhcp6Notify (
  IN EFI_EVENT  Event,
  IN VOID       *Context
  )
{
  //
  // Intentionally empty — the harness does not need to react to these
  // signals; we just need a valid function pointer for CreateEvent().
  //
}

/**
  Exercise EfiDhcp6Stop in various states.

  Stop() resets the IA state to Dhcp6Init and releases all IPv6
  addresses.  This function tests Stop in multiple scenarios to
  exercise different cleanup paths inside the driver:
  - Stop after Configure only (no Start)
  - Stop without prior Configure (unconfigured path)
  - Stop after Configure + Start (full lifecycle teardown)
  - Double-Stop (second Stop is a no-op / safe)

  SubOptions byte controls behavior:
    Bit 0 (0x01): Pass NULL as 'This' pointer (INVALID_PARAMETER)
    Bit 1 (0x02): Stop without Configure (unconfigured error path)
    Bit 2 (0x04): Double-Stop -- call Stop twice consecutively
    Bit 3 (0x08): Configure + Start + Stop (full lifecycle teardown)

  @param[in]  FuzzCtx     Fuzz context for config construction.
  @param[in]  SubOptions  Bitmask controlling stop scenarios.
**/
STATIC
VOID
FuzzStop (
  IN MOCK_FUZZ_CONTEXT  *FuzzCtx,
  IN UINT8               SubOptions
  )
{
  EFI_STATUS                Status;
  EFI_DHCP6_CONFIG_DATA     Config;
  EFI_DHCP6_RETRANSMISSION  Retrans;
  EFI_EVENT                 IaEvent;

  //
  // Bit 0: test NULL This -> INVALID_PARAMETER
  //
  if (SubOptions & 0x01) {
    mDhcp6->Stop (NULL);
    return;
  }

  //
  // Bit 1: Stop without Configure -- tests unconfigured / no-IA path
  //
  if (SubOptions & 0x02) {
    mDhcp6->Configure (mDhcp6, NULL);
    mDhcp6->Stop (mDhcp6);
    return;
  }

  BuildFuzzConfig (&Config, &Retrans, FuzzCtx);

  //
  // Bit 3: full lifecycle -- Configure + Start(async) + Stop.
  // Exercises IA teardown when Solicit has been sent and UDP_IO,
  // timers, and pending events are active.
  //
  if (SubOptions & 0x08) {
    Status = gBS->CreateEvent (EVT_NOTIFY_SIGNAL, TPL_CALLBACK, DummyDhcp6Notify, NULL, &IaEvent);
    if (EFI_ERROR (Status)) {
      CleanupFuzzConfig (&Config);
      return;
    }

    Config.IaInfoEvent = IaEvent;

    Status = mDhcp6->Configure (mDhcp6, &Config);
    if (!EFI_ERROR (Status)) {
      mDhcp6->Start (mDhcp6);
      MockFuzzContextAdvanceTime (FuzzCtx);
      mDhcp6->Stop (mDhcp6);

      //
      // Bit 2: double-stop after Start+Stop
      //
      if (SubOptions & 0x04) {
        mDhcp6->Stop (mDhcp6);
      }

      mDhcp6->Configure (mDhcp6, NULL);
    }

    CleanupFuzzConfig (&Config);
    gBS->CloseEvent (IaEvent);
    return;
  }

  //
  // Default: Configure -> Stop -> unconfigure
  //
  Status = mDhcp6->Configure (mDhcp6, &Config);
  if (!EFI_ERROR (Status)) {
    mDhcp6->Stop (mDhcp6);

    //
    // Bit 2: double-stop
    //
    if (SubOptions & 0x04) {
      mDhcp6->Stop (mDhcp6);
    }

    mDhcp6->Configure (mDhcp6, NULL);
  }

  CleanupFuzzConfig (&Config);
}

/**
  Stub callback for InfoRequest — always returns EFI_SUCCESS to finish
  the information-request exchange immediately if a reply arrives.
**/
STATIC
EFI_STATUS
EFIAPI
InfoRequestReplyCallback (
  IN EFI_DHCP6_PROTOCOL  *This,
  IN VOID                *Context,
  IN EFI_DHCP6_PACKET    *Packet
  )
{
  return EFI_SUCCESS;
}

/**
  Exercise EfiDhcp6Start with fuzz-controlled configuration.

  Start() initiates the DHCPv6 S.A.R.R process.  With IaInfoEvent set,
  Start() operates in async mode -- it builds and sends a Solicit
  packet via Dhcp6SendSolicitMsg, then returns immediately.

  The Solicit packet construction uses the fuzz-controlled IaDescriptor,
  retransmission parameters, and OptionList from BuildFuzzConfig().

  SubOptions byte controls edge-case behaviors:
    Bit 0 (0x01): Pass NULL as 'This' pointer (INVALID_PARAMETER)
    Bit 1 (0x02): Attempt double-start (ALREADY_STARTED path)
    Bit 2 (0x04): Start without Configure (ACCESS_DENIED path)

  @param[in]  FuzzCtx     Fuzz context for config and time advance.
  @param[in]  SubOptions  Bitmask controlling edge-case behaviors.
**/
STATIC
VOID
FuzzStart (
  IN MOCK_FUZZ_CONTEXT  *FuzzCtx,
  IN UINT8               SubOptions
  )
{
  EFI_STATUS                Status;
  EFI_DHCP6_CONFIG_DATA     Config;
  EFI_DHCP6_RETRANSMISSION  Retrans;
  EFI_EVENT                 IaEvent;

  //
  // Bit 0: test NULL This -> INVALID_PARAMETER
  //
  if (SubOptions & 0x01) {
    mDhcp6->Start (NULL);
    return;
  }

  //
  // Bit 2: Start without Configure -> ACCESS_DENIED.
  // Ensures the unconfigured-instance guard works.
  //
  if (SubOptions & 0x04) {
    mDhcp6->Configure (mDhcp6, NULL);
    mDhcp6->Start (mDhcp6);
    return;
  }

  //
  // Create a notification event for async mode.
  // IaInfoEvent != NULL ensures Start() returns immediately after
  // sending the Solicit, without blocking in a poll loop.
  //
  Status = gBS->CreateEvent (EVT_NOTIFY_SIGNAL, TPL_CALLBACK, DummyDhcp6Notify, NULL, &IaEvent);
  if (EFI_ERROR (Status)) {
    return;
  }

  //
  // Build config from fuzz data -- all IaDescriptor fields,
  // retransmission parameters, and OptionList entries come from
  // the fuzzer.
  //
  BuildFuzzConfig (&Config, &Retrans, FuzzCtx);
  Config.IaInfoEvent           = IaEvent;
  Config.SolicitRetransmission = &Retrans;

  Status = mDhcp6->Configure (mDhcp6, &Config);
  if (!EFI_ERROR (Status)) {
    //
    // Start in async mode -- exercises Dhcp6SendSolicitMsg
    // packet construction: ClientId, IA option, OptionRequest,
    // Elapsed Time, and user-supplied options are serialized.
    //
    Status = mDhcp6->Start (mDhcp6);
    DEBUG ((DEBUG_VERBOSE, "TestDhcp6Driver: Start(async) = %r\n", Status));

    //
    // Bit 1: attempt double-start -> ALREADY_STARTED.
    // The second Start() should fail because the S.A.R.R process
    // is already in progress.
    //
    if (!EFI_ERROR (Status) && (SubOptions & 0x02)) {
      mDhcp6->Start (mDhcp6);
    }

    //
    // Advance time -- timer ticks, UDP completion callbacks
    //
    MockFuzzContextAdvanceTime (FuzzCtx);

    //
    // Cleanup: Stop resets IA to Dhcp6Init, then unconfigure
    //
    mDhcp6->Stop (mDhcp6);
    mDhcp6->Configure (mDhcp6, NULL);
  }

  CleanupFuzzConfig (&Config);
  gBS->CloseEvent (IaEvent);
}

/**
  Exercise EfiDhcp6InfoRequest with fuzz-controlled parameters.

  InfoRequest() sends a DHCPv6 Information-Request message to obtain
  configuration without IPv6 address assignment.  It has the most
  parameters of any protocol function -- all are fuzz-driven:

  - SendClientId:     fuzz-controlled boolean
  - OptionRequest:    OpCode and data from fuzz buffer
  - OptionCount:      fuzz-controlled (0 or with OptionList entries)
  - OptionList[]:     fuzz-controlled additional option TLVs
  - Retransmission:   Irt/Mrc/Mrt/Mrd from fuzz data
  - TimeoutEvent:     always non-NULL (async mode for safety)
  - ReplyCallback:    valid callback (NULL tested via SubOptions)
  - CallbackContext:  NULL (not exercised further)

  SubOptions byte controls edge-case behaviors:
    Bit 0 (0x01): Pass NULL as 'This' pointer (INVALID_PARAMETER)
    Bit 1 (0x02): Fuzz OptionRequest OpCode (not fixed to ORO=6)
    Bit 2 (0x04): Include fuzz-controlled OptionList entries
    Bit 3 (0x08): Pass NULL ReplyCallback (INVALID_PARAMETER)
    Bit 4 (0x10): Pass NULL Retransmission (INVALID_PARAMETER)

  @param[in]  FuzzCtx     Fuzz context for parameter construction.
  @param[in]  SubOptions  Bitmask controlling edge-case behaviors.
**/
STATIC
VOID
FuzzInfoRequest (
  IN MOCK_FUZZ_CONTEXT  *FuzzCtx,
  IN UINT8               SubOptions
  )
{
  EFI_STATUS                Status;
  EFI_DHCP6_RETRANSMISSION  Retrans;
  EFI_EVENT                 TimeoutEvent;
  BOOLEAN                   SendClientId;
  EFI_DHCP6_PACKET_OPTION   *OptionRequest;
  EFI_DHCP6_PACKET_OPTION   **OptionList;
  UINT32                    OptionCount;
  UINT16                    ReqOpCode;
  UINTN                     DataLen;
  UINTN                     OptSize;
  UINT32                    Idx;

  //
  // Bit 0: test NULL This -> INVALID_PARAMETER
  //
  if (SubOptions & 0x01) {
    ZeroMem (&Retrans, sizeof (Retrans));
    Retrans.Irt = 1;
    Retrans.Mrc = 1;
    OptSize = sizeof (EFI_DHCP6_PACKET_OPTION) + 2;
    OptionRequest = AllocateZeroPool (OptSize);
    if (OptionRequest != NULL) {
      ReqOpCode = HTONS (6);
      CopyMem (&OptionRequest->OpCode, &ReqOpCode, sizeof (UINT16));
      mDhcp6->InfoRequest (
                NULL, FALSE, OptionRequest, 0, NULL,
                &Retrans, NULL, InfoRequestReplyCallback, NULL
                );
      FreePool (OptionRequest);
    }
    return;
  }

  //
  // Build Retransmission from fuzz data -- raw values.
  // Driver validates that Mrc and Mrd are not both zero.
  //
  Retrans.Irt = MockFuzzContextGetU32 (FuzzCtx);
  Retrans.Mrc = MockFuzzContextGetU32 (FuzzCtx);
  Retrans.Mrt = MockFuzzContextGetU32 (FuzzCtx);
  Retrans.Mrd = MockFuzzContextGetU32 (FuzzCtx);

  //
  // Build OptionRequest from fuzz -- OpCode and data.
  // In real usage this is always DHCP6_OPT_ORO (6) with body
  // containing 2-byte option codes the client wants from the server.
  //
  DataLen = (UINTN)MockFuzzContextGetU8 (FuzzCtx);
  OptSize = sizeof (EFI_DHCP6_PACKET_OPTION) + DataLen;
  OptionRequest = AllocateZeroPool (OptSize);
  if (OptionRequest == NULL) {
    return;
  }

  //
  // Bit 1: fuzz the OptionRequest OpCode.
  // Real callers always use DHCP6_OPT_ORO (6), but the driver
  // validates this field -- invalid OpCodes exercise INVALID_PARAMETER.
  //
  if (SubOptions & 0x02) {
    ReqOpCode = MockFuzzContextGetU16 (FuzzCtx);
  } else {
    ReqOpCode = HTONS (6);
  }
  CopyMem (&OptionRequest->OpCode, &ReqOpCode, sizeof (UINT16));
  {
    UINT16  NetLen = HTONS ((UINT16)DataLen);
    CopyMem (&OptionRequest->OpLen, &NetLen, sizeof (UINT16));
  }

  //
  // Fill OptionRequest data from fuzz buffer -- contains the list of
  // requested option codes (each 2 bytes, network order).
  //
  if ((DataLen > 0) && (MockFuzzContextRemaining (FuzzCtx) > 0)) {
    UINTN  Avail   = MockFuzzContextRemaining (FuzzCtx);
    UINTN  CopyLen = (Avail < DataLen) ? Avail : DataLen;
    {
      UINT8  *Src = MockFuzzContextConsume (FuzzCtx, CopyLen);
      if (Src != NULL) {
        CopyMem (OptionRequest->Data, Src, CopyLen);
      }
    }
  }

  //
  // SendClientId from fuzz data -- controls whether Client Identifier
  // option is included in the Information-Request packet.
  //
  SendClientId = (BOOLEAN)(MockFuzzContextGetU8 (FuzzCtx) & 1);

  //
  // Bit 2: build fuzz-controlled OptionList -- additional DHCPv6 options
  // appended to the Information-Request packet body.
  // Examples: Vendor Class, User Class, custom vendor options.
  //
  OptionList  = NULL;
  OptionCount = 0;
  if (SubOptions & 0x04) {
    UINT8  RawCount = MockFuzzContextGetU8 (FuzzCtx);
    OptionCount = (UINT32)(RawCount % 9);  // 0..8, OOM cap

    if (OptionCount > 0) {
      OptionList = AllocateZeroPool (OptionCount * sizeof (EFI_DHCP6_PACKET_OPTION *));
      if (OptionList == NULL) {
        OptionCount = 0;
      } else {
        for (Idx = 0; Idx < OptionCount; Idx++) {
          UINT16  OpCode  = MockFuzzContextGetU16 (FuzzCtx);
          UINT8   OptLen  = MockFuzzContextGetU8 (FuzzCtx);
          UINTN   OSize;

          if (OptLen > 64) {
            OptLen = 64;
          }
          OSize = sizeof (EFI_DHCP6_PACKET_OPTION) + OptLen;
          OptionList[Idx] = AllocateZeroPool (OSize);
          if (OptionList[Idx] == NULL) {
            OptionCount = Idx;
            break;
          }

          OptionList[Idx]->OpCode = OpCode;
          OptionList[Idx]->OpLen  = HTONS (OptLen);

          if ((OptLen > 0) && (MockFuzzContextRemaining (FuzzCtx) > 0)) {
            UINTN  A = MockFuzzContextRemaining (FuzzCtx);
            UINTN  C = (A < (UINTN)OptLen) ? A : (UINTN)OptLen;
            UINT8  *Src = MockFuzzContextConsume (FuzzCtx, C);

            if (Src != NULL) {
              CopyMem (OptionList[Idx]->Data, Src, C);
            }
          }
        }
      }
    }
  }

  //
  // Create timeout event for async mode -- ensures InfoRequest
  // returns immediately after sending, without blocking.
  //
  Status = gBS->CreateEvent (EVT_NOTIFY_SIGNAL, TPL_CALLBACK, DummyDhcp6Notify, NULL, &TimeoutEvent);
  if (!EFI_ERROR (Status)) {
    //
    // Bit 3: NULL ReplyCallback -> INVALID_PARAMETER
    // Bit 4: NULL Retransmission -> INVALID_PARAMETER
    //
    Status = mDhcp6->InfoRequest (
               mDhcp6,
               SendClientId,
               OptionRequest,
               OptionCount,
               OptionList,
               (SubOptions & 0x10) ? NULL : &Retrans,
               TimeoutEvent,
               (SubOptions & 0x08) ? NULL : InfoRequestReplyCallback,
               NULL
               );
    DEBUG ((DEBUG_VERBOSE, "TestDhcp6Driver: InfoRequest = %r\n", Status));

    //
    // Advance time -- timeout and reply callbacks
    //
    MockFuzzContextAdvanceTime (FuzzCtx);

    gBS->CloseEvent (TimeoutEvent);
  }

  FreePool (OptionRequest);

  //
  // Free OptionList entries and array
  //
  if (OptionList != NULL) {
    for (Idx = 0; Idx < OptionCount; Idx++) {
      if (OptionList[Idx] != NULL) {
        FreePool (OptionList[Idx]);
      }
    }
    FreePool (OptionList);
  }
}

/**
  Exercise EfiDhcp6RenewRebind -- validation path.

  After Configure, the IA is in Dhcp6Init state (not Dhcp6Bound), so
  RenewRebind returns ACCESS_DENIED.  This exercises parameter validation
  and instance-lookup code inside EfiDhcp6RenewRebind.

  Arguments derived from fuzzer:
  - RebindRequest boolean: bit 0 of SubOptions
  - Config (IaDescriptor, retransmission, OptionList): from FuzzCtx

  SubOptions byte controls edge-case behaviors:
    Bit 0 (0x01): RebindRequest parameter (FALSE=Renew, TRUE=Rebind)
    Bit 1 (0x02): Pass NULL as 'This' pointer (INVALID_PARAMETER)
    Bit 2 (0x04): Skip configure -- test unconfigured RenewRebind

  @param[in]  FuzzCtx     Fuzz context for config construction.
  @param[in]  SubOptions  Bitmask controlling parameters and edge cases.
**/
STATIC
VOID
FuzzRenewRebind (
  IN MOCK_FUZZ_CONTEXT  *FuzzCtx,
  IN UINT8               SubOptions
  )
{
  EFI_STATUS                Status;
  EFI_DHCP6_CONFIG_DATA     Config;
  EFI_DHCP6_RETRANSMISSION  Retrans;
  BOOLEAN                   RebindReq;

  //
  // Bit 0: RebindRequest -- controls whether Renew or Rebind is sent
  //
  RebindReq = (BOOLEAN)((SubOptions & 0x01) != 0);

  //
  // Bit 1: test NULL This -> INVALID_PARAMETER
  //
  if (SubOptions & 0x02) {
    mDhcp6->RenewRebind (NULL, RebindReq);
    return;
  }

  //
  // Bit 2: test without Configure -> ACCESS_DENIED (no IA)
  //
  if (SubOptions & 0x04) {
    mDhcp6->Configure (mDhcp6, NULL);
    mDhcp6->RenewRebind (mDhcp6, RebindReq);
    return;
  }

  //
  // Configure with fuzz-driven config, then attempt RenewRebind.
  // In Dhcp6Init state, RenewRebind -> ACCESS_DENIED.
  //
  BuildFuzzConfig (&Config, &Retrans, FuzzCtx);

  Status = mDhcp6->Configure (mDhcp6, &Config);
  if (!EFI_ERROR (Status)) {
    Status = mDhcp6->RenewRebind (mDhcp6, RebindReq);
    DEBUG ((DEBUG_VERBOSE, "TestDhcp6Driver: RenewRebind(%d) = %r\n",
            RebindReq, Status));

    mDhcp6->Configure (mDhcp6, NULL);
  }

  CleanupFuzzConfig (&Config);
}

/**
  Exercise EfiDhcp6Decline -- validation path.

  After Configure, the IA is not in Dhcp6Bound, so Decline returns
  ACCESS_DENIED.  This exercises parameter validation, address-count
  checks, and instance lookup inside EfiDhcp6Decline.

  Arguments derived from fuzzer:
  - AddressCount: from FuzzCtx (capped at 16 for OOM)
  - Addresses: IPv6 address content from FuzzCtx
  - Config (IaDescriptor, retransmission, OptionList): from FuzzCtx

  SubOptions byte controls edge-case behaviors:
    Bit 0 (0x01): Pass NULL as 'This' pointer (INVALID_PARAMETER)
    Bit 1 (0x02): Use AddressCount=0, Addresses=NULL (INVALID_PARAMETER)
    Bit 2 (0x04): Use non-zero AddressCount with NULL Addresses ptr

  @param[in]  FuzzCtx     Fuzz context for parameter construction.
  @param[in]  SubOptions  Bitmask controlling edge-case behaviors.
**/
STATIC
VOID
FuzzDecline (
  IN MOCK_FUZZ_CONTEXT  *FuzzCtx,
  IN UINT8               SubOptions
  )
{
  EFI_STATUS                Status;
  EFI_DHCP6_CONFIG_DATA     Config;
  EFI_DHCP6_RETRANSMISSION  Retrans;
  EFI_IPv6_ADDRESS          *Addrs;
  UINT32                    AddrCount;
  UINTN                     AddrSize;

  //
  // Bit 0: test NULL This -> INVALID_PARAMETER
  //
  if (SubOptions & 0x01) {
    EFI_IPv6_ADDRESS  DummyAddr;
    ZeroMem (&DummyAddr, sizeof (DummyAddr));
    mDhcp6->Decline (NULL, 1, &DummyAddr);
    return;
  }

  //
  // Bit 1: test AddressCount=0, Addresses=NULL -> INVALID_PARAMETER
  //
  if (SubOptions & 0x02) {
    mDhcp6->Decline (mDhcp6, 0, NULL);
    return;
  }

  //
  // Bit 2: non-zero count with NULL Addresses -> INVALID_PARAMETER
  //
  if (SubOptions & 0x04) {
    mDhcp6->Decline (mDhcp6, 1, NULL);
    return;
  }

  BuildFuzzConfig (&Config, &Retrans, FuzzCtx);

  //
  // Build address list from fuzz data -- count capped at 16 for OOM,
  // forced to at least 1 to avoid INVALID_PARAMETER on count=0.
  //
  AddrCount = (UINT32)MockFuzzContextGetU8 (FuzzCtx);
  if (AddrCount > 16) {
    AddrCount = 16;
  }
  if (AddrCount == 0) {
    AddrCount = 1;
  }

  AddrSize = AddrCount * sizeof (EFI_IPv6_ADDRESS);
  Addrs = AllocateZeroPool (AddrSize);
  if (Addrs == NULL) {
    CleanupFuzzConfig (&Config);
    return;
  }

  //
  // Fill addresses from fuzz data
  //
  if (MockFuzzContextRemaining (FuzzCtx) > 0) {
    UINTN  CopyLen = (MockFuzzContextRemaining (FuzzCtx) < AddrSize)
                      ? MockFuzzContextRemaining (FuzzCtx) : AddrSize;
    UINT8  *Src = MockFuzzContextConsume (FuzzCtx, CopyLen);

    if (Src != NULL) {
      CopyMem (Addrs, Src, CopyLen);
    }
  }

  Status = mDhcp6->Configure (mDhcp6, &Config);
  if (!EFI_ERROR (Status)) {
    //
    // Decline in Dhcp6Init -> ACCESS_DENIED (expected)
    //
    Status = mDhcp6->Decline (mDhcp6, AddrCount, Addrs);
    DEBUG ((DEBUG_VERBOSE, "TestDhcp6Driver: Decline(%u addrs) = %r\n",
            AddrCount, Status));

    mDhcp6->Configure (mDhcp6, NULL);
  }

  FreePool (Addrs);
  CleanupFuzzConfig (&Config);
}

/**
  Exercise EfiDhcp6Release -- validation path.

  After Configure, the IA is not in Dhcp6Bound, so Release returns
  ACCESS_DENIED.  This exercises parameter validation and instance
  lookup inside EfiDhcp6Release.

  Arguments derived from fuzzer:
  - AddressCount: from FuzzCtx (0 = release-all, >0 = specific addrs)
  - Addresses: IPv6 address content from FuzzCtx
  - Config (IaDescriptor, retransmission, OptionList): from FuzzCtx

  SubOptions byte controls edge-case behaviors:
    Bit 0 (0x01): Pass NULL as 'This' pointer (INVALID_PARAMETER)
    Bit 1 (0x02): Release-all mode (AddressCount=0, Addresses=NULL)
    Bit 2 (0x04): Non-zero AddressCount with NULL Addresses ptr

  @param[in]  FuzzCtx     Fuzz context for parameter construction.
  @param[in]  SubOptions  Bitmask controlling edge-case behaviors.
**/
STATIC
VOID
FuzzRelease (
  IN MOCK_FUZZ_CONTEXT  *FuzzCtx,
  IN UINT8               SubOptions
  )
{
  EFI_STATUS                Status;
  EFI_DHCP6_CONFIG_DATA     Config;
  EFI_DHCP6_RETRANSMISSION  Retrans;
  EFI_IPv6_ADDRESS          *Addrs;
  UINT32                    AddrCount;
  UINTN                     AddrSize;

  //
  // Bit 0: test NULL This -> INVALID_PARAMETER
  //
  if (SubOptions & 0x01) {
    EFI_IPv6_ADDRESS  DummyAddr;
    ZeroMem (&DummyAddr, sizeof (DummyAddr));
    mDhcp6->Release (NULL, 1, &DummyAddr);
    return;
  }

  //
  // Bit 1: release-all mode -- AddressCount=0, Addresses=NULL.
  // Tests the bulk-release path.
  //
  if (SubOptions & 0x02) {
    BuildFuzzConfig (&Config, &Retrans, FuzzCtx);
    Status = mDhcp6->Configure (mDhcp6, &Config);
    if (!EFI_ERROR (Status)) {
      mDhcp6->Release (mDhcp6, 0, NULL);
      mDhcp6->Configure (mDhcp6, NULL);
    }
    CleanupFuzzConfig (&Config);
    return;
  }

  //
  // Bit 2: non-zero count with NULL Addresses -> INVALID_PARAMETER
  //
  if (SubOptions & 0x04) {
    mDhcp6->Release (mDhcp6, 1, NULL);
    return;
  }

  BuildFuzzConfig (&Config, &Retrans, FuzzCtx);

  //
  // Build address list from fuzz data.
  // Count=0 means release-all, capped at 16 for OOM.
  //
  AddrCount = (UINT32)MockFuzzContextGetU8 (FuzzCtx);
  if (AddrCount > 16) {
    AddrCount = 16;
  }

  Addrs    = NULL;
  AddrSize = AddrCount * sizeof (EFI_IPv6_ADDRESS);
  if (AddrCount > 0) {
    Addrs = AllocateZeroPool (AddrSize);
    if (Addrs == NULL) {
      CleanupFuzzConfig (&Config);
      return;
    }

    if (MockFuzzContextRemaining (FuzzCtx) > 0) {
      UINTN  CopyLen = (MockFuzzContextRemaining (FuzzCtx) < AddrSize)
                        ? MockFuzzContextRemaining (FuzzCtx) : AddrSize;
      UINT8  *Src = MockFuzzContextConsume (FuzzCtx, CopyLen);

      if (Src != NULL) {
        CopyMem (Addrs, Src, CopyLen);
      }
    }
  }

  Status = mDhcp6->Configure (mDhcp6, &Config);
  if (!EFI_ERROR (Status)) {
    //
    // Release in Dhcp6Init -> ACCESS_DENIED (expected)
    //
    Status = mDhcp6->Release (mDhcp6, AddrCount, Addrs);
    DEBUG ((DEBUG_VERBOSE, "TestDhcp6Driver: Release(%u addrs) = %r\n",
            AddrCount, Status));

    mDhcp6->Configure (mDhcp6, NULL);
  }

  if (Addrs != NULL) {
    FreePool (Addrs);
  }

  CleanupFuzzConfig (&Config);
}

/**
  Exercise ServiceBinding CreateChild + DestroyChild cycle.

  Creates a new child, fetches its Dhcp6 protocol, exercises
  GetModeData on it, then destroys the child.
**/
STATIC
VOID
FuzzServiceBindingCreateDestroy (
  IN MOCK_FUZZ_CONTEXT  *FuzzCtx
  )
{
  EFI_STATUS             Status;
  EFI_HANDLE             NewChild;
  EFI_DHCP6_PROTOCOL     *NewDhcp6;
  EFI_DHCP6_MODE_DATA    ModeData;

  if (mServiceBinding == NULL) {
    return;
  }

  NewChild = NULL;
  Status = mServiceBinding->CreateChild (mServiceBinding, &NewChild);
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_VERBOSE, "TestDhcp6Driver: SB.CreateChild = %r\n", Status));
    return;
  }

  //
  // Get Dhcp6 protocol from the new child
  //
  Status = gBS->HandleProtocol (
                  NewChild,
                  &gEfiDhcp6ProtocolGuid,
                  (VOID **)&NewDhcp6
                  );
  if (!EFI_ERROR (Status)) {
    //
    // Lightly exercise the new instance
    //
    ZeroMem (&ModeData, sizeof (ModeData));
    NewDhcp6->GetModeData (NewDhcp6, &ModeData, NULL);
    if (ModeData.ClientId != NULL) {
      FreePool (ModeData.ClientId);
    }
    if (ModeData.Ia != NULL) {
      if (ModeData.Ia->ReplyPacket != NULL) {
        FreePool (ModeData.Ia->ReplyPacket);
      }
      FreePool (ModeData.Ia);
    }
  }

  //
  // Destroy the child
  //
  Status = mServiceBinding->DestroyChild (mServiceBinding, NewChild);
  DEBUG ((DEBUG_VERBOSE, "TestDhcp6Driver: SB.DestroyChild = %r\n", Status));

  //
  // Also test INVALID_PARAMETER paths on ServiceBinding
  //
  mServiceBinding->CreateChild (mServiceBinding, NULL);
  mServiceBinding->DestroyChild (mServiceBinding, NULL);
}

/**
  Exercise Configure(NULL) — the unconfigure/cleanup path.

  Configure with valid data, then call Configure(NULL) to deregister.
**/
STATIC
VOID
FuzzConfigureNull (
  IN MOCK_FUZZ_CONTEXT  *FuzzCtx
  )
{
  EFI_STATUS                Status;
  EFI_DHCP6_CONFIG_DATA     Config;
  EFI_DHCP6_RETRANSMISSION  Retrans;

  BuildFuzzConfig (&Config, &Retrans, FuzzCtx);

  Status = mDhcp6->Configure (mDhcp6, &Config);
  if (!EFI_ERROR (Status)) {
    //
    // Unconfigure — exercises the cleanup / de-registration path
    //
    Status = mDhcp6->Configure (mDhcp6, NULL);
    DEBUG ((DEBUG_VERBOSE, "TestDhcp6Driver: Configure(NULL) = %r\n", Status));
  }

  CleanupFuzzConfig (&Config);
}

/**
  Exercise Start without prior Configure — tests error paths.
**/
STATIC
VOID
FuzzStartUnconfigured (
  VOID
  )
{
  EFI_STATUS  Status;

  //
  // Ensure we are unconfigured
  //
  mDhcp6->Configure (mDhcp6, NULL);

  //
  // Start without config → ACCESS_DENIED
  //
  Status = mDhcp6->Start (mDhcp6);
  DEBUG ((DEBUG_VERBOSE, "TestDhcp6Driver: Start(unconfigured) = %r  (expect ACCESS_DENIED)\n", Status));

  //
  // Start with NULL This → INVALID_PARAMETER
  //
  Status = mDhcp6->Start (NULL);
  DEBUG ((DEBUG_VERBOSE, "TestDhcp6Driver: Start(NULL) = %r  (expect INVALID_PARAMETER)\n", Status));

  //
  // Stop with NULL This → INVALID_PARAMETER
  //
  Status = mDhcp6->Stop (NULL);
  DEBUG ((DEBUG_VERBOSE, "TestDhcp6Driver: Stop(NULL) = %r  (expect INVALID_PARAMETER)\n", Status));
}

/**
  Full lifecycle: Configure → Start (async) → Stop → Configure(NULL).

  Exercises the complete happy path through the driver.
**/
STATIC
VOID
FuzzFullLifecycle (
  IN MOCK_FUZZ_CONTEXT  *FuzzCtx
  )
{
  EFI_STATUS                Status;
  EFI_DHCP6_CONFIG_DATA     Config;
  EFI_DHCP6_RETRANSMISSION  Retrans;
  EFI_EVENT                 IaEvent;
  EFI_DHCP6_MODE_DATA       ModeData;

  Status = gBS->CreateEvent (EVT_NOTIFY_SIGNAL, TPL_CALLBACK, DummyDhcp6Notify, NULL, &IaEvent);
  if (EFI_ERROR (Status)) {
    return;
  }

  BuildFuzzConfig (&Config, &Retrans, FuzzCtx);
  Config.IaInfoEvent           = IaEvent;
  Config.SolicitRetransmission = &Retrans;

  Status = mDhcp6->Configure (mDhcp6, &Config);
  if (EFI_ERROR (Status)) {
    CleanupFuzzConfig (&Config);
    gBS->CloseEvent (IaEvent);
    return;
  }

  //
  // Read config back
  //
  ZeroMem (&ModeData, sizeof (ModeData));
  mDhcp6->GetModeData (mDhcp6, &ModeData, NULL);
  if (ModeData.ClientId != NULL) {
    FreePool (ModeData.ClientId);
  }
  if (ModeData.Ia != NULL) {
    if (ModeData.Ia->ReplyPacket != NULL) {
      FreePool (ModeData.Ia->ReplyPacket);
    }
    FreePool (ModeData.Ia);
  }

  //
  // Start (async) — exercises Dhcp6SendSolicitMsg
  //
  Status = mDhcp6->Start (mDhcp6);
  DEBUG ((DEBUG_VERBOSE, "TestDhcp6Driver: FullLifecycle Start = %r\n", Status));

  //
  // Advance time so timer/completion callbacks fire during lifecycle
  //
  MockFuzzContextAdvanceTime (FuzzCtx);

  //
  // Stop — cleans up IA, resets state to Dhcp6Init
  //
  mDhcp6->Stop (mDhcp6);

  //
  // Unconfigure
  //
  mDhcp6->Configure (mDhcp6, NULL);

  CleanupFuzzConfig (&Config);
  gBS->CloseEvent (IaEvent);
}


//=============================================================================
// API 15: DriverStop  (terminal DriverBinding Stop — no restart)
//=============================================================================

/**
  Exercise the full driver teardown path as a terminal operation.

  In real firmware, DriverBinding happens once during platform init;
  drivers are not stopped and restarted during normal operation.  This
  handler mirrors that model: after Stop, the harness state is invalidated
  and no further API calls should reference the old protocol pointers.

  Teardown sequence:
    1. Unconfigure the protocol instance (Configure(NULL) — idempotent).
    2. DriverBinding.Stop(children) — destroys child instances.
    3. DriverBinding.Stop(service)  — frees Service, UdpIo, ClientId.
    4. NULL all module pointers + MockProtocolResetAll().
**/
STATIC
VOID
FuzzDriverStop (
  IN MOCK_FUZZ_CONTEXT  *FuzzCtx
  )
{
  EFI_STATUS  Status;

  if (mServiceBinding == NULL || mChildHandle == NULL) {
    return;
  }

  //
  // Unconfigure — release any active session (idempotent if already unconfigured).
  //
  if (mDhcp6 != NULL) {
    mDhcp6->Configure (mDhcp6, NULL);
  }

  //
  // Destroy child instance, then disconnect all drivers.
  //
  mServiceBinding->DestroyChild (mServiceBinding, mChildHandle);
  mChildHandle = NULL;
  HostDisconnectDrivers (gFuzzHandle, gHostDriverRegistry);
  //
  // Terminal: NULL all module pointers — no restart.
  //
  mDhcp6          = NULL;
  mChildHandle    = NULL;
  mServiceBinding = NULL;

  //
  // Reset all mock protocol state so no stale DPC / token callbacks fire.
  //
  MockProtocolResetAll ();

  DEBUG ((DEBUG_VERBOSE, "TestDhcp6Driver: Driver Stop complete (terminal)\n"));
}


/**
  Helper: Configure the instance and Start in async mode to initiate the
  S.A.R.R (Solicit → Advertise → Request → Reply) exchange.

  The UDP6 sub-context must contain the full exchange sequence:
    TX(Solicit) + RX(Advertise) + TX(Request) + RX(Reply) + RX terminator

  Because MockUdp6 processes synchronously, the entire SARR exchange
  completes inside the Start() call if the packets match:
    1. Solicit TX → 1 byte from UDP6 sub-context
    2. Advertise RX → LE16 len + DHCPv6 payload (must have matching XID,
       ClientId, ServerId, IA option)
    3. Request TX → 1 byte
    4. Reply RX → LE16 len + DHCPv6 payload (must have matching XID,
       ClientId, ServerId, IA with addresses, StatusCode=Success)
    5. Next RX → 0 or exhausted → terminates the Receive chain

  After Start returns, the instance may be in Dhcp6Bound (SARR succeeded)
  or Dhcp6Selecting/Dhcp6Init (packets didn't match or were malformed).

  @param[in]   FuzzCtx   Fuzz context for config construction.
  @param[out]  IaEvent   Created IaInfoEvent (caller closes it).

  @retval TRUE   Instance is in Dhcp6Bound state after Start.
  @retval FALSE  Did not reach Bound (Start failed, packets didn't match).
**/
STATIC
BOOLEAN
HelperPerformSARR (
  IN  MOCK_FUZZ_CONTEXT  *FuzzCtx,
  OUT EFI_EVENT          *IaEvent
  )
{
  EFI_STATUS                Status;
  EFI_DHCP6_CONFIG_DATA     Config;
  EFI_DHCP6_RETRANSMISSION  Retrans;
  EFI_DHCP6_MODE_DATA       ModeData;

  *IaEvent = NULL;

  Status = gBS->CreateEvent (EVT_NOTIFY_SIGNAL, TPL_CALLBACK, DummyDhcp6Notify, NULL, IaEvent);
  if (EFI_ERROR (Status)) {
    return FALSE;
  }

  BuildFuzzConfig (&Config, &Retrans, FuzzCtx);
  Config.IaInfoEvent           = *IaEvent;
  Config.SolicitRetransmission = &Retrans;

  Status = mDhcp6->Configure (mDhcp6, &Config);
  CleanupFuzzConfig (&Config);
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, "TestDhcp6Driver: SARR Configure failed = %r\n", Status));
    gBS->CloseEvent (*IaEvent);
    *IaEvent = NULL;
    return FALSE;
  }

  //
  // Start in async mode (IaInfoEvent != NULL).
  // Start() sends Solicit and registers UdpIoRecvDatagram, then returns
  // immediately.  The deferred TX/RX events are registered in the event
  // pump but are NOT automatically fired.  We must advance time explicitly
  // to drive the SARR state machine to completion:
  //
  //   Advance Pump 1: fires TX Solicit completion (closed → removed from pump)
  //   Advance Pump 2: fires RX Advertise delivery → Dhcp6ReceivePacket processes
  //           it, sends Request TX, registers new Receive → new TX+RX
  //           events added during this pump; RX Reply may fire in the
  //           same sweep (event count grows dynamically in the loop)
  //   Advance Pump 3: fires any remaining events (TX Request completion, etc.)
  //
  // Each pump call consumes 4 bytes from FuzzCtx (UINT16 bitmask +
  // UINT16 timer delta).  When fuzz data is exhausted, defaults to
  // mask=0xFFFF (fire all) and timer=200ms.
  //
  Status = mDhcp6->Start (mDhcp6);
  DEBUG ((DEBUG_VERBOSE, "TestDhcp6Driver: SARR Start = %r\n", Status));

  if (!EFI_ERROR (Status)) {
    UINTN  Round;
    for (Round = 0; Round < 3; Round++) {
      MockFuzzContextAdvanceTime (FuzzCtx);
    }
  }

  //
  // Check if we reached Dhcp6Bound by reading ModeData.
  //
  ZeroMem (&ModeData, sizeof (ModeData));
  mDhcp6->GetModeData (mDhcp6, &ModeData, NULL);

  if (ModeData.ClientId != NULL) {
    FreePool (ModeData.ClientId);
  }

  if (ModeData.Ia != NULL) {
    BOOLEAN  IsBound = (ModeData.Ia->State == Dhcp6Bound);

    if (ModeData.Ia->ReplyPacket != NULL) {
      FreePool (ModeData.Ia->ReplyPacket);
    }

    FreePool (ModeData.Ia);
    return IsBound;
  }

  return FALSE;
}

/**
  Exercise the full S.A.R.R (Solicit-Advertise-Request-Reply) exchange.

  This is the HIGHEST-VALUE API for Dhcp6Dxe fuzzing.  It exercises the
  entire packet receive/parse/state-transition code in Dhcp6Io.c that is
  unreachable when only testing individual APIs:

    Dhcp6ReceivePacket      → packet dispatching by XID
    Dhcp6HandleStateful     → ClientId/ServerId validation
    Dhcp6HandleAdvertiseMsg → preference, rapid commit, status code
    Dhcp6SelectAdvertiseMsg → server unicast, UpdateIaInfo
    Dhcp6HandleReplyMsg     → status code branches, IA update
    Dhcp6UpdateIaInfo       → T1/T2 validation, inner option parsing
    Dhcp6SeekInnerOptionSafe → IA_NA/IA_TA inner option safety
    Dhcp6SeekStsOption      → two-level status code search
    Dhcp6GenerateIaCb       → address parsing, IA allocation
    Dhcp6ParseAddrOption    → IPv6 address extraction

  The UDP6 sub-context must contain the full packet exchange data.
  The seed generator (gen_dhcp6_seeds.py) produces seeds with properly
  structured Advertise and Reply packets that match the deterministic
  ClientId DUID and XID.

  SubOptions byte controls post-SARR behavior:
    Bit 0 (0x01): Exercise GetModeData in Bound state
    Bit 1 (0x02): Advance time after SARR (timer tick → Renew/Rebind)
    Bit 2 (0x04): Call Stop from Bound (→ sends Release message)

  @param[in]  FuzzCtx     Fuzz context for config + API parameters.
  @param[in]  SubOptions  Bitmask controlling post-SARR behavior.
**/
STATIC
VOID
FuzzStartSARR (
  IN MOCK_FUZZ_CONTEXT  *FuzzCtx,
  IN UINT8               SubOptions
  )
{
  EFI_EVENT             IaEvent;
  BOOLEAN               Bound;
  EFI_DHCP6_MODE_DATA   ModeData;

  Bound = HelperPerformSARR (FuzzCtx, &IaEvent);
  DEBUG ((DEBUG_VERBOSE, "TestDhcp6Driver: SARR Bound=%d\n", Bound));

  if (Bound) {
    //
    // Bit 0: Get full mode data in Bound state.
    // Exercises deep-copy of IA with addresses, ReplyPacket, ClientId.
    //
    if (SubOptions & 0x01) {
      EFI_DHCP6_CONFIG_DATA  CfgOut;
      ZeroMem (&ModeData, sizeof (ModeData));
      ZeroMem (&CfgOut, sizeof (CfgOut));

      mDhcp6->GetModeData (mDhcp6, &ModeData, &CfgOut);

      //
      // Free deep-copied ModeData
      //
      if (ModeData.ClientId != NULL) {
        FreePool (ModeData.ClientId);
      }

      if (ModeData.Ia != NULL) {
        if (ModeData.Ia->ReplyPacket != NULL) {
          FreePool (ModeData.Ia->ReplyPacket);
        }

        FreePool (ModeData.Ia);
      }

      //
      // Free deep-copied ConfigData
      //
      if (CfgOut.OptionList != NULL) {
        UINT32  i;
        for (i = 0; i < CfgOut.OptionCount; i++) {
          if (CfgOut.OptionList[i] != NULL) {
            FreePool (CfgOut.OptionList[i]);
          }
        }

        FreePool (CfgOut.OptionList);
      }

      if (CfgOut.SolicitRetransmission != NULL) {
        FreePool (CfgOut.SolicitRetransmission);
      }
    }

    //
    // Bit 1: Advance time in Bound state.
    // The timer tick may trigger Renew (LeaseTime > T1) or Rebind
    // (LeaseTime > T2), or link-change detection → Confirm.
    //
    if (SubOptions & 0x02) {
      MockFuzzContextAdvanceTime (FuzzCtx);
    }

    //
    // Bit 2: Stop from Bound state.
    // In Bound/Renewing/Rebinding states, Stop sends a Release message
    // before cleanup.  This exercises Dhcp6SendReleaseMsg from real
    // Bound-state with a valid IA and ReplyPacket (for ServerId lookup).
    //
    if (SubOptions & 0x04) {
      mDhcp6->Stop (mDhcp6);
      mDhcp6->Configure (mDhcp6, NULL);
      if (IaEvent != NULL) {
        gBS->CloseEvent (IaEvent);
      }

      return;
    }
  }

  //
  // Cleanup: Stop resets IA to Dhcp6Init, Configure(NULL) de-registers
  //
  mDhcp6->Stop (mDhcp6);
  mDhcp6->Configure (mDhcp6, NULL);
  if (IaEvent != NULL) {
    gBS->CloseEvent (IaEvent);
  }
}

/**
  Exercise Bound-state protocol APIs after completing a SARR exchange.

  This API handler first performs a full SARR to reach Dhcp6Bound, then
  exercises APIs that require the Bound state: RenewRebind, Decline,
  and Release.  These APIs are ACCESS_DENIED without Bound state, so
  the existing individual API handlers only reach validation code.

  The UDP6 sub-context must contain bytes for:
    Phase 1 (SARR): TX + Advertise + TX + Reply + terminator
    Phase 2 (Bound op): TX + Reply-to-op + terminator

  SubOptions controls which Bound-state API to exercise:
    Bit 0 (0x01): RenewRebind(Renew=FALSE) — sends Renew, expects Reply
    Bit 1 (0x02): RenewRebind(Rebind=TRUE) — sends Rebind, expects Reply
    Bit 2 (0x04): Decline — sends Decline with fuzz-controlled addresses
    Bit 3 (0x08): Release — sends Release with fuzz-controlled addresses
    Bit 4 (0x10): Release-all — sends Release(0, NULL) to release all

  @param[in]  FuzzCtx     Fuzz context for config + API parameters.
  @param[in]  SubOptions  Bitmask controlling which Bound-state API to exercise.
**/
STATIC
VOID
FuzzBoundOps (
  IN MOCK_FUZZ_CONTEXT  *FuzzCtx,
  IN UINT8               SubOptions
  )
{
  EFI_EVENT         IaEvent;
  BOOLEAN           Bound;
  EFI_STATUS        Status;

  Bound = HelperPerformSARR (FuzzCtx, &IaEvent);
  if (!Bound) {
    //
    // SARR didn't reach Bound — nothing meaningful to exercise.
    //
    mDhcp6->Stop (mDhcp6);
    mDhcp6->Configure (mDhcp6, NULL);
    if (IaEvent != NULL) {
      gBS->CloseEvent (IaEvent);
    }

    return;
  }

  //
  // Now in Dhcp6Bound — exercise real Bound-state APIs.
  //

  if (SubOptions & 0x01) {
    //
    // Renew: Dhcp6Bound → Dhcp6Renewing.
    // Sends Renew message with ServerId from ReplyPacket.
    // The Reply (from UDP6 sub-context) may transition back to Bound
    // or trigger NoBinding → Request flow.
    //
    Status = mDhcp6->RenewRebind (mDhcp6, FALSE);
    DEBUG ((DEBUG_VERBOSE, "TestDhcp6Driver: BoundOps Renew = %r\n", Status));
    MockFuzzContextAdvanceTime (FuzzCtx);
  } else if (SubOptions & 0x02) {
    //
    // Rebind: Dhcp6Bound → Dhcp6Rebinding.
    // Sends Rebind (multicast, no ServerId).
    //
    Status = mDhcp6->RenewRebind (mDhcp6, TRUE);
    DEBUG ((DEBUG_VERBOSE, "TestDhcp6Driver: BoundOps Rebind = %r\n", Status));
    MockFuzzContextAdvanceTime (FuzzCtx);
  } else if (SubOptions & 0x04) {
    //
    // Decline: Dhcp6Bound → Dhcp6Declining.
    // Uses fuzz-controlled address list (addresses from the IA).
    //
    EFI_DHCP6_MODE_DATA   ModeData;
    ZeroMem (&ModeData, sizeof (ModeData));
    mDhcp6->GetModeData (mDhcp6, &ModeData, NULL);

    if ((ModeData.Ia != NULL) && (ModeData.Ia->IaAddressCount > 0)) {
      //
      // Decline the first address from the IA — this is a real address
      // that was assigned via SARR, so the driver's CheckAddress passes.
      //
      Status = mDhcp6->Decline (mDhcp6, 1, &ModeData.Ia->IaAddress[0].IpAddress);
      DEBUG ((DEBUG_VERBOSE, "TestDhcp6Driver: BoundOps Decline = %r\n", Status));
      MockFuzzContextAdvanceTime (FuzzCtx);
    }

    if (ModeData.ClientId != NULL) {
      FreePool (ModeData.ClientId);
    }

    if (ModeData.Ia != NULL) {
      if (ModeData.Ia->ReplyPacket != NULL) {
        FreePool (ModeData.Ia->ReplyPacket);
      }

      FreePool (ModeData.Ia);
    }
  } else if (SubOptions & 0x08) {
    //
    // Release with specific addresses from the IA.
    //
    EFI_DHCP6_MODE_DATA   ModeData;
    ZeroMem (&ModeData, sizeof (ModeData));
    mDhcp6->GetModeData (mDhcp6, &ModeData, NULL);

    if ((ModeData.Ia != NULL) && (ModeData.Ia->IaAddressCount > 0)) {
      Status = mDhcp6->Release (mDhcp6, 1, &ModeData.Ia->IaAddress[0].IpAddress);
      DEBUG ((DEBUG_VERBOSE, "TestDhcp6Driver: BoundOps Release = %r\n", Status));
      MockFuzzContextAdvanceTime (FuzzCtx);
    }

    if (ModeData.ClientId != NULL) {
      FreePool (ModeData.ClientId);
    }

    if (ModeData.Ia != NULL) {
      if (ModeData.Ia->ReplyPacket != NULL) {
        FreePool (ModeData.Ia->ReplyPacket);
      }

      FreePool (ModeData.Ia);
    }
  } else if (SubOptions & 0x10) {
    //
    // Release-all: Release(0, NULL) sends Release for all IA addresses.
    //
    Status = mDhcp6->Release (mDhcp6, 0, NULL);
    DEBUG ((DEBUG_VERBOSE, "TestDhcp6Driver: BoundOps ReleaseAll = %r\n", Status));
    MockFuzzContextAdvanceTime (FuzzCtx);
  }

  //
  // Cleanup
  //
  mDhcp6->Stop (mDhcp6);
  mDhcp6->Configure (mDhcp6, NULL);
  if (IaEvent != NULL) {
    gBS->CloseEvent (IaEvent);
  }
}


//=============================================================================
// ToolChainHarnessLib entry points
//=============================================================================

/**
  Return the number of fuzz bytes consumed during bootstrap (InitializeHarness).

  These bytes are reserved for mock protocol consumption during driver
  initialization and are NOT visible to RunTestHarness.  ToolChainHarnessLib
  sets a Limit before ProcessLibraryConstructorList / InitializeHarness,
  then advances past this region before calling RunTestHarness.

  Bootstrap layout (consumed by mock protocols during DriverBinding.Start):
    [0..3] MockRng::GetRNG(4)  — PseudoRandomU32 in Dhcp6CreateService
    [4..5] MockUdp6::Receive   — LE16 length hint during UdpIoRecvDatagram

  After bootstrap, RunTestHarness reads a 4-byte header
  (ApiSelector, SubOptions, Udp6Budget), carves a UDP6 sub-context, and
  registers it so runtime MockUdp6 calls use the dedicated region.

  @return  Bootstrap region size in bytes (6).
**/
UINTN
EFIAPI
GetBootstrapSize (
  VOID
  )
{
  return 6;
}

/**
  Return maximum fuzz input size.

  @return Maximum buffer size the harness can handle.
**/
UINTN
EFIAPI
GetMaxBufferSize (
  VOID
  )
{
  return MAX_FUZZ_INPUT_SIZE;
}

/**
  One-time initialization: drive the full DriverBinding → ServiceBinding →
  CreateChild flow to get a live EFI_DHCP6_PROTOCOL instance.

  @retval EFI_SUCCESS  Harness ready to fuzz.
**/
EFI_STATUS
EFIAPI
InitializeHarness (
  VOID
  )
{
  EFI_STATUS                    Status;

  DEBUG ((DEBUG_INFO, "TestDhcp6Driver: InitializeHarness\n"));

  //
  // NOTE: Generic setup (FuzzGetContext, MockEventSetAdvanceContext) is
  // now handled by ToolChainHarnessLib automatically.
  //

  //
  // Dispatch driver via ConnectController (same path as DXE dispatcher).
  //
  Status = HostDispatchDrivers (gFuzzHandle, gHostDriverRegistry);
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, "TestDhcp6Driver: HostDispatchDrivers failed: %r\n", Status));
    return Status;
  }
  //
  // Step 4: Get the ServiceBinding installed by Start()
  //
  Status = gBS->HandleProtocol (
                  gFuzzHandle,
                  &gEfiDhcp6ServiceBindingProtocolGuid,
                  (VOID **)&mServiceBinding
                  );
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, "TestDhcp6Driver: Can't find ServiceBinding: %r\n", Status));
    return Status;
  }

  //
  // Step 5: CreateChild — creates DHCP6_INSTANCE with Timer,
  // installs gEfiDhcp6ProtocolGuid on a new child handle.
  //
  mChildHandle = NULL;
  Status = mServiceBinding->CreateChild (mServiceBinding, &mChildHandle);
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, "TestDhcp6Driver: CreateChild failed: %r\n", Status));
    return Status;
  }

  //
  // Step 6: Get the Dhcp6 protocol from the child handle.
  //
  Status = gBS->HandleProtocol (
                  mChildHandle,
                  &gEfiDhcp6ProtocolGuid,
                  (VOID **)&mDhcp6
                  );
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, "TestDhcp6Driver: Can't find Dhcp6 on child: %r\n", Status));
    return Status;
  }

  DEBUG ((DEBUG_INFO, "TestDhcp6Driver: Harness initialized, Dhcp6=%p\n", mDhcp6));
  return EFI_SUCCESS;
}

/**
  Process one fuzz input.

  Reads a 4-byte header (ApiSelector, SubOptions, Udp6Budget), carves
  an independent sub-context for UDP6 runtime consumption, registers it
  with the protocol context registry, then dispatches to the selected
  API handler.

  The sub-context separation ensures the fuzzer can independently vary
  UDP6 network conditions (TX failures, RX payloads) without disturbing
  API parameter bytes, and vice versa.

  @param[in]  FuzzCtx  Shared fuzz context (from ToolChainHarnessLib).
                        Bootstrap bytes have already been skipped via
                        AdvanceTo — this context starts at the harness
                        payload region.
**/
VOID
EFIAPI
RunTestHarness (
  IN MOCK_FUZZ_CONTEXT  *FuzzCtx
  )
{
  UINT8              ApiSelector;
  UINT8              SubOptions;
  UINT16             Udp6Budget;
  MOCK_FUZZ_CONTEXT  Udp6Sub;
  EFI_STATUS         SubCtxStatus;

  if (mDhcp6 == NULL || FuzzCtx == NULL || MockFuzzContextRemaining (FuzzCtx) < 4) {
    return;
  }

  //
  // ── Header: 4 bytes ──
  // Byte 0: API selector  (mod API_COUNT)
  // Byte 1: Sub-options   (API-specific bitmask)
  // Byte 2-3: UDP6 Budget (LE16 — bytes reserved for UDP6 sub-context)
  //
  ApiSelector = MockFuzzContextGetU8 (FuzzCtx);
  SubOptions  = MockFuzzContextGetU8 (FuzzCtx);
  Udp6Budget  = MockFuzzContextGetU16 (FuzzCtx);

  //
  // Cap the UDP6 budget to prevent one iteration from consuming an
  // unreasonable portion of the fuzz buffer.  4096 is generous —
  // a typical Start() triggers ~3 bytes of UDP6 (1 TX + 2 RX hint).
  //
  if (Udp6Budget > 4096) {
    Udp6Budget = 4096;
  }

  //
  // ── Carve a sub-context for UDP6 runtime consumption ──
  //
  // CreateSubContext consumes Udp6Budget bytes from FuzzCtx and wraps
  // them in an independent MOCK_FUZZ_CONTEXT (Udp6Sub).
  //
  // After registration, MockUdp6's ResolveContext() finds the override
  // and reads Transmit statuses / Receive payloads from Udp6Sub instead
  // of the shared pool.  This makes UDP6 byte consumption independent
  // of API parameter bytes.
  //
  // When Udp6Budget is 0 (for APIs that don't use UDP6, e.g. Parse),
  // CreateSubContext returns SUCCESS with an immediately-exhausted
  // sub-context — MockUdp6 falls back to deterministic defaults.
  //
  SubCtxStatus = MockFuzzContextCreateSubContext (FuzzCtx, &Udp6Sub, Udp6Budget);
  if (!EFI_ERROR (SubCtxStatus)) {
    MockFuzzContextSetProtocolContext (&gEfiUdp6ProtocolGuid, &Udp6Sub);
  }

  //
  // ── Remaining FuzzCtx bytes are now exclusively for API payloads ──
  //

  switch (ApiSelector % API_COUNT) {
    case API_GET_MODE_DATA:
      FuzzGetModeData (FuzzCtx, SubOptions);
      break;

    case API_CONFIGURE:
      FuzzConfigure (FuzzCtx, SubOptions);
      break;

    case API_CONFIGURE_AND_GET:
      FuzzConfigure (FuzzCtx, SubOptions | 0x02);  // force GetModeData-after
      break;

    case API_PARSE:
      FuzzParse (FuzzCtx, SubOptions);
      break;

    case API_CONFIGURE_AND_STOP:
      FuzzStop (FuzzCtx, SubOptions);
      break;

    case API_GET_MODE_NULL_ONLY:
      //
      // Both output pointers NULL -- tests early-return INVALID_PARAMETER path
      //
      FuzzGetModeData (FuzzCtx, 0x00);
      break;

    case API_START:
      FuzzStart (FuzzCtx, SubOptions);
      break;

    case API_INFO_REQUEST:
      FuzzInfoRequest (FuzzCtx, SubOptions);
      break;

    case API_RENEW_REBIND:
      FuzzRenewRebind (FuzzCtx, SubOptions);
      break;

    case API_DECLINE:
      FuzzDecline (FuzzCtx, SubOptions);
      break;

    case API_RELEASE:
      FuzzRelease (FuzzCtx, SubOptions);
      break;

    case API_SB_CREATE_DESTROY:
      FuzzServiceBindingCreateDestroy (FuzzCtx);
      break;

    case API_CONFIGURE_NULL:
      FuzzConfigureNull (FuzzCtx);
      break;

    case API_START_UNCONFIGURED:
      FuzzStartUnconfigured ();
      break;

    case API_FULL_LIFECYCLE:
      FuzzFullLifecycle (FuzzCtx);
      break;

    case API_DRIVER_STOP:
      FuzzDriverStop (FuzzCtx);
      break;

    case API_START_SARR:
      FuzzStartSARR (FuzzCtx, SubOptions);
      break;

    case API_BOUND_OPS:
      FuzzBoundOps (FuzzCtx, SubOptions);
      break;

    default:
      break;
  }

  //
  // ── Cleanup: remove protocol context override ──
  //
  // Clear the UDP6 sub-context registration so it doesn't leak into
  // the time advance phase or any callback that might fire during cleanup.
  //
  if (!EFI_ERROR (SubCtxStatus)) {
    MockFuzzContextClearProtocolContext (&gEfiUdp6ProtocolGuid);
  }

  //
  // Pump all auto-registered events.  The UINT16 bitmask consumed from the
  // fuzz buffer decides which completion/timer callbacks fire this
  // iteration, giving the fuzzer fine-grained control over async paths.
  //
  MockFuzzContextAdvanceTime (FuzzCtx);
}

/**
  Cleanup any resources allocated by InitializeHarness.
**/
VOID
EFIAPI
CleanupHarness (
  VOID
  )
{
  //
  // Nothing to clean up — mock protocols and driver structures persist
  // for the lifetime of the fuzzing process.
  //
}
