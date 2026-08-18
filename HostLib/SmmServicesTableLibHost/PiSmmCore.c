/** @file
  SMM Core Main Entry Point — Host-based SMST initialization.

  Copyright (c) 2009 - 2018, Intel Corporation. All rights reserved.<BR>
  SPDX-License-Identifier: BSD-2-Clause-Patent

  ## AUDIT ##
  Defines the global gSmmCoreSmst structure (EFI_SMM_SYSTEM_TABLE2) that
  is the heart of the SMM services. All function pointers are wired to
  the host-side implementations.

  Fields wired to real implementations:
    SmmInstallConfigurationTable  → InstallConfigurationTable.c
    SmmAllocatePool/SmmFreePool   → SmmServicesTableLibHost.c (malloc/free)
    SmmAllocatePages/SmmFreePages → SmmServicesTableLibHost.c (malloc/free)
    SmmInstallProtocolInterface   → Handle.c (full database)
    SmmUninstallProtocolInterface → Handle.c
    SmmHandleProtocol             → Handle.c
    SmmRegisterProtocolNotify     → Notify.c
    SmmLocateHandle               → Locate.c
    SmmLocateProtocol             → Locate.c

  Fields stubbed (not needed for host fuzzing):
    SmmIo (MemRead/MemWrite/IoRead/IoWrite) → SmmEfiNotAvailableYetArg5
    SmmStartupThisAp → EFI_UNSUPPORTED (was NULL, fixed to prevent crash)

  Data fields:
    CurrentlyExecutingCpu = 0, NumberOfCpus = 0 (single-threaded host)
    CpuSaveStateSize/CpuSaveState = NULL (no real CPU save state)
    NumberOfTableEntries = 0, SmmConfigurationTable = NULL (initially empty)
**/

#include "PiSmmCore.h"

///
/// Forward declaration for the SmmStartupThisAp stub in SmmServicesTableLibHost.c
///
EFI_STATUS
EFIAPI
SmmStartupThisAp (
  IN EFI_AP_PROCEDURE  Procedure,
  IN UINTN             CpuNumber,
  IN OUT VOID          *ProcArguments OPTIONAL
  );

//
// SMM Core global variable for SMM System Table.  Only accessed as a physical structure in SMRAM.
//
EFI_SMM_SYSTEM_TABLE2  gSmmCoreSmst = {
  {
    SMM_SMST_SIGNATURE,
    EFI_SMM_SYSTEM_TABLE2_REVISION,
    sizeof (gSmmCoreSmst.Hdr)
  },
  NULL,                          // SmmFirmwareVendor
  0,                             // SmmFirmwareRevision
  SmmInstallConfigurationTable,
  {
    {
      (EFI_SMM_CPU_IO2) SmmEfiNotAvailableYetArg5,       // SmmMemRead
      (EFI_SMM_CPU_IO2) SmmEfiNotAvailableYetArg5        // SmmMemWrite
    },
    {
      (EFI_SMM_CPU_IO2) SmmEfiNotAvailableYetArg5,       // SmmIoRead
      (EFI_SMM_CPU_IO2) SmmEfiNotAvailableYetArg5        // SmmIoWrite
    }
  },
  SmmAllocatePool,
  SmmFreePool,
  SmmAllocatePages,
  SmmFreePages,
  (EFI_SMM_STARTUP_THIS_AP) SmmStartupThisAp,   // Was NULL — now safe stub
  0,                             // CurrentlyExecutingCpu
  0,                             // NumberOfCpus
  NULL,                          // CpuSaveStateSize
  NULL,                          // CpuSaveState
  0,                             // NumberOfTableEntries
  NULL,                          // SmmConfigurationTable
  SmmInstallProtocolInterface,
  SmmUninstallProtocolInterface,
  SmmHandleProtocol,
  SmmRegisterProtocolNotify,
  SmmLocateHandle,
  SmmLocateProtocol,
  SmiManage,
  SmiHandlerRegister,
  SmiHandlerUnRegister
};

/**
  Placeholder function for SMST services that are not available.

  Used for SmmIo (MemRead/MemWrite/IoRead/IoWrite) which are not
  needed in the host fuzzing environment.  Drivers that use IoLib
  or MmioLib go through separate library implementations instead.

  @param  Arg1-Arg5  Undefined parameters.
  @return EFI_NOT_AVAILABLE_YET
**/
EFI_STATUS
EFIAPI
SmmEfiNotAvailableYetArg5 (
  UINTN Arg1,
  UINTN Arg2,
  UINTN Arg3,
  UINTN Arg4,
  UINTN Arg5
  )
{
  return EFI_NOT_AVAILABLE_YET;
}

