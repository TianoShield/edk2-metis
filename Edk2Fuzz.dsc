## @file Edk2Fuzz.dsc
#  Edk2Fuzz Platform Description — minimal Dhcp6 fuzz harness build.
#
#  Layout:
#    MockProtocols/       Shared mock protocol implementations
#    FuzzHarness/         Self-contained harnesses
#    HostLib/             Host-compatible UEFI library implementations
#    Infrastructure/      ToolChainHarnessLib (AFL fork-server entry point)
#
#  Usage:
#    build -p Edk2Fuzz.dsc -m FuzzHarness/NetworkPkg/Dhcp6Dxe/TestDhcp6Driver/TestDhcp6Driver.inf -a X64 -t GCC5
#    build -p Edk2Fuzz.dsc -m FuzzHarness/NetworkPkg/Dhcp6Dxe/TestDhcp6Driver/TestDhcp6Driver.inf -a X64 -t AFL
#    build -p Edk2Fuzz.dsc -m FuzzHarness/NetworkPkg/Dhcp6Dxe/TestDhcp6Driver/TestDhcp6Driver.inf -a X64 -t AFLCLANG -D EDK2_ROOT=/src/edk2
#
#  Derived from TianoFuzz (layout) and HBFAplus (sources).
#
#  Copyright (c) 2024-2026, Edk2Fuzz Contributors. All rights reserved.
#  SPDX-License-Identifier: BSD-2-Clause-Patent
##

[Defines]
  PLATFORM_NAME                  = Edk2FuzzPkg
  PLATFORM_GUID                  = 6B0D1C2E-4A83-4F19-9C5D-7E2F84B1A036
  PLATFORM_VERSION               = 1.0
  DSC_SPECIFICATION              = 0x00010005
  OUTPUT_DIRECTORY               = Build/Edk2FuzzPkg
  SUPPORTED_ARCHITECTURES        = IA32|X64
  BUILD_TARGETS                  = DEBUG|RELEASE|NOOPT
  SKUID_IDENTIFIER               = DEFAULT
  DEFINE EDK2FUZZ_PATCH_DXE_CONSTRUCTORS = TRUE
  # OSS-Fuzz overrides with -D EDK2_ROOT=/src/edk2.
  DEFINE EDK2_ROOT = $(WORKSPACE)/edk2

#=============================================================================
# Library Classes
#=============================================================================

[LibraryClasses]
  #---------------------------------------------------------------------------
  # Host Libraries (HostLib) — libc-based UEFI service implementations
  #---------------------------------------------------------------------------
  BaseLib|HostLib/BaseLibHost/BaseLibHost.inf
  BaseMemoryLib|HostLib/BaseMemoryLibHost/BaseMemoryLibHost.inf
  MemoryAllocationLib|HostLib/MemoryAllocationLibHost/MemoryAllocationLibHost.inf
  DebugLib|HostLib/DebugLibHost/DebugLibHost.inf
  UefiBootServicesTableLib|HostLib/UefiBootServicesTableLibHost/UefiBootServicesTableLibHost.inf
  UefiRuntimeServicesTableLib|HostLib/UefiRuntimeServicesTableLibHost/UefiRuntimeServicesTableLibHost.inf
  DevicePathLib|HostLib/UefiDevicePathLibHost/UefiDevicePathLibHost.inf
  CacheMaintenanceLib|HostLib/BaseCacheMaintenanceLibHost/BaseCacheMaintenanceLibHost.inf
  TimerLib|HostLib/BaseTimerLibHost/BaseTimerLibHost.inf
  HobLib|HostLib/HobLibHost/HobLibHost.inf
  DxeServicesTableLib|HostLib/DxeServicesTableLibHost/DxeServicesTableLibHost.inf
  SmmServicesTableLib|HostLib/SmmServicesTableLibHost/SmmServicesTableLibHost.inf
  MmServicesTableLib|HostLib/SmmServicesTableLibHost/SmmServicesTableLibHost.inf
  SmmMemLib|HostLib/SmmMemLibHost/SmmMemLibHost.inf
  PeiServicesLib|MdePkg/Library/PeiServicesLib/PeiServicesLib.inf
  PeiServicesTablePointerLib|HostLib/PeiServicesTablePointerLibHost/PeiServicesTablePointerLibHost.inf
  UefiDriverEntryPoint|HostLib/UefiDriverEntryPointHost/UefiDriverEntryPointHost.inf
  PeimEntryPoint|HostLib/PeimEntryPointHost/PeimEntryPointHost.inf
  SynchronizationLib|HostLib/SimpleSynchronizationLib/SimpleSynchronizationLib.inf
  LockBoxLib|HostLib/LockBoxStubLib/LockBoxStubLib.inf

  #---------------------------------------------------------------------------
  # Fuzzing Infrastructure
  #---------------------------------------------------------------------------
  FuzzContextLib|HostLib/FuzzContextLib/FuzzContextLib.inf
  RegisterFilterLib|HostLib/RegisterFilterLibHost/RegisterFilterLibHost.inf
  IoLib|MdePkg/Library/BaseIoLibIntrinsic/BaseIoLibIntrinsic.inf
  ToolChainHarnessLib|Infrastructure/ToolChainHarnessLib/ToolChainHarnessLib.inf
  HostDispatcherLib|HostLib/HostDispatcherLib/HostDispatcherLib.inf

  #---------------------------------------------------------------------------
  # EDK2 stock libraries
  #---------------------------------------------------------------------------
  PrintLib|MdePkg/Library/BasePrintLib/BasePrintLib.inf
  PcdLib|MdePkg/Library/BasePcdLibNull/BasePcdLibNull.inf
  PerformanceLib|MdePkg/Library/BasePerformanceLibNull/BasePerformanceLibNull.inf
  ReportStatusCodeLib|MdePkg/Library/BaseReportStatusCodeLibNull/BaseReportStatusCodeLibNull.inf
  UefiLib|MdePkg/Library/UefiLib/UefiLib.inf
  UefiRuntimeLib|MdePkg/Library/UefiRuntimeLib/UefiRuntimeLib.inf
  DebugPrintErrorLevelLib|MdePkg/Library/BaseDebugPrintErrorLevelLib/BaseDebugPrintErrorLevelLib.inf

  #---------------------------------------------------------------------------
  # NetworkPkg libraries needed by Dhcp6Dxe
  #---------------------------------------------------------------------------
  NetLib|NetworkPkg/Library/DxeNetLib/DxeNetLib.inf
  UdpIoLib|NetworkPkg/Library/DxeUdpIoLib/DxeUdpIoLib.inf
  DpcLib|NetworkPkg/Library/DxeDpcLib/DxeDpcLib.inf
  IpIoLib|NetworkPkg/Library/DxeIpIoLib/DxeIpIoLib.inf

  #---------------------------------------------------------------------------
  # Mock protocol libraries (Dhcp6 stack)
  #---------------------------------------------------------------------------
  MockgEfiSimpleNetworkProtocolGuid|MockProtocols/NetworkPkg/SnpDxe/MockgEfiSimpleNetworkProtocolGuid/MockgEfiSimpleNetworkProtocolGuid.inf
  MockgEfiIp6ConfigProtocolGuid|MockProtocols/NetworkPkg/Ip6Dxe/MockgEfiIp6ConfigProtocolGuid/MockgEfiIp6ConfigProtocolGuid.inf
  MockgEfiIp6ProtocolGuid|MockProtocols/NetworkPkg/Ip6Dxe/MockgEfiIp6ProtocolGuid/MockgEfiIp6ProtocolGuid.inf
  MockgEfiIp6ServiceBindingProtocolGuid|MockProtocols/NetworkPkg/Ip6Dxe/MockgEfiIp6ServiceBindingProtocolGuid/MockgEfiIp6ServiceBindingProtocolGuid.inf
  MockgEfiUdp6ProtocolGuid|MockProtocols/NetworkPkg/Udp6Dxe/MockgEfiUdp6ProtocolGuid/MockgEfiUdp6ProtocolGuid.inf
  MockgEfiUdp6ServiceBindingProtocolGuid|MockProtocols/NetworkPkg/Udp6Dxe/MockgEfiUdp6ServiceBindingProtocolGuid/MockgEfiUdp6ServiceBindingProtocolGuid.inf
  MockgEfiDpcProtocolGuid|MockProtocols/NetworkPkg/DpcDxe/MockgEfiDpcProtocolGuid/MockgEfiDpcProtocolGuid.inf
  MockgEfiRngProtocolGuid|MockProtocols/SecurityPkg/RandomNumberGenerator/RngDxe/MockgEfiRngProtocolGuid/MockgEfiRngProtocolGuid.inf

[PcdsFixedAtBuild]
  gEfiMdePkgTokenSpaceGuid.PcdDebugPropertyMask|0x2F
  gEfiMdePkgTokenSpaceGuid.PcdDebugPrintErrorLevel|0xFFFFFFFF

  # Force DUID-LLT type for DHCPv6 Client Identifier (deterministic seed corpora)
  gEfiNetworkPkgTokenSpaceGuid.PcdDhcp6UidType|0x1

#=============================================================================
# Components — Fuzz Harnesses
#=============================================================================

[Components]
  #---------------------------------------------------------------------------
  # Dhcp6Dxe — Full driver flow (DriverBinding → ServiceBinding → CreateChild)
  #---------------------------------------------------------------------------
  FuzzHarness/NetworkPkg/Dhcp6Dxe/TestDhcp6Driver/TestDhcp6Driver.inf {
    <LibraryClasses>
      NULL|NetworkPkg/Dhcp6Dxe/Dhcp6Dxe.inf
      NULL|MockProtocols/NetworkPkg/DpcDxe/MockgEfiDpcProtocolGuid/MockgEfiDpcProtocolGuid.inf
      NULL|MockProtocols/SecurityPkg/RandomNumberGenerator/RngDxe/MockgEfiRngProtocolGuid/MockgEfiRngProtocolGuid.inf
      NULL|MockProtocols/NetworkPkg/SnpDxe/MockgEfiSimpleNetworkProtocolGuid/MockgEfiSimpleNetworkProtocolGuid.inf
      NULL|MockProtocols/NetworkPkg/Ip6Dxe/MockgEfiIp6ConfigProtocolGuid/MockgEfiIp6ConfigProtocolGuid.inf
      NULL|MockProtocols/NetworkPkg/Udp6Dxe/MockgEfiUdp6ProtocolGuid/MockgEfiUdp6ProtocolGuid.inf
      NULL|MockProtocols/NetworkPkg/Udp6Dxe/MockgEfiUdp6ServiceBindingProtocolGuid/MockgEfiUdp6ServiceBindingProtocolGuid.inf
    <BuildOptions>
      GCC:*_*_*_CC_FLAGS = -I$(EDK2_ROOT)/NetworkPkg/Dhcp6Dxe
  }

#=============================================================================
# Build Options
#=============================================================================

[BuildOptions]
  GCC:*_*_*_CC_FLAGS = -Wall -Wno-unused-but-set-variable

!include Conf/Edk2FuzzBuildOption.dsc
