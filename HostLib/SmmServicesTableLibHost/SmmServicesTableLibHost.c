/** @file
  SMM Services Table Library — Host-based implementation for fuzzing.

  Copyright (c) 2009 - 2018, Intel Corporation. All rights reserved.<BR>
  SPDX-License-Identifier: BSD-2-Clause-Patent

  ## AUDIT SUMMARY ##
  Upstream: edk2/MdePkg/Library/SmmServicesTableLib/SmmServicesTableLib.c
  Purpose : Exports gSmst (EFI_SMM_SYSTEM_TABLE2*) and gMmst (EFI_MM_SYSTEM_TABLE*)
            pointing to a host-side gSmmCoreSmst structure defined in PiSmmCore.c.

  Globals:
    gSmst  — pointer to gSmmCoreSmst, satisfies SmmServicesTableLib LIBRARY_CLASS
    gMmst  — same pointer cast, satisfies MmServicesTableLib LIBRARY_CLASS

  This file implements the SMST service functions that are simplifications of
  the real PI SMM Core services, suitable for host-based fuzzing:

    SmmAllocatePages  — malloc-backed, ignores Type/MemoryType (OK for fuzzing)
    SmmFreePages      — free(), ignores NumberOfPages (OK for glibc free)
    SmmAllocatePool   — malloc-backed, ignores PoolType
    SmmFreePool       — free()
    SmiManage         — full dispatch (ported from PiSmmCore/Smi.c)
    SmiHandlerRegister   — full registration with GUID-keyed entries
    SmiHandlerUnRegister — full with deferred removal during dispatch
    SmmStartupThisAp     — stub returning EFI_UNSUPPORTED (no AP support)
    InSmm()              — always returns TRUE (host is simulating SMM context)

  Full protocol database (install/uninstall/locate/handle/notify) is provided
  by Handle.c, Locate.c, Notify.c — faithful copies of upstream PiSmmCore.
  Configuration table management is in InstallConfigurationTable.c.

  Differences from upstream:
    - Memory allocation uses libc malloc/free (enables ASan/MSan for fuzzing)
    - SmmIo CPU I/O stubs return EFI_NOT_AVAILABLE_YET (rarely used by drivers)
    - No SMRAM management, no multiprocessor AP support
    - SmmStartupThisAp returns EFI_UNSUPPORTED instead of NULL (prevents crash)
    - InSmm() always returns TRUE
    - SMI dispatch is fully functional (supports Register/Manage/Unregister)

  Suitable for rehosting any SMM/MM driver that uses protocol database,
  memory allocation, and configuration tables.
**/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include "PiSmmCore.h"
#include <Library/UefiBootServicesTableLib.h>
#include <Protocol/SmmBase2.h>

extern EFI_SMM_SYSTEM_TABLE2  gSmmCoreSmst;

///
/// Global pointer to the SMM System Table — consumed by all SMM drivers
/// via SmmServicesTableLib. Initially NULL; set by constructor via
/// EFI_SMM_BASE2_PROTOCOL.GetSmstLocation(), mirroring upstream.
///
EFI_SMM_SYSTEM_TABLE2  *gSmst      = NULL;

///
/// Global pointer for MM (Management Mode) Services Table — identical to
/// gSmst but typed as EFI_MM_SYSTEM_TABLE* for MM_STANDALONE drivers.
/// Initially NULL; set by constructor.
///
EFI_MM_SYSTEM_TABLE    *gMmst      = NULL;

/**
  Constructor for the host-based SMM Services Table Library.

  Mirrors upstream SmmServicesTableLibConstructor which:
    1. Locates EFI_SMM_BASE2_PROTOCOL via BootServices->LocateProtocol
    2. Calls GetSmstLocation() to populate gSmst

  In the host environment, MockgEfiSmmBase2ProtocolGuid provides the mock
  protocol on gFuzzHandle, which returns &gSmmCoreSmst.

  @retval RETURN_SUCCESS  gSmst and gMmst set successfully.
**/
RETURN_STATUS
EFIAPI
SmmServicesTableLibConstructor (
  VOID
  )
{
  EFI_STATUS               Status;
  EFI_SMM_BASE2_PROTOCOL   *SmmBase2;
  EFI_SMM_SYSTEM_TABLE2    *Smst;

  SmmBase2 = NULL;
  Smst     = NULL;

  //
  // Locate the SMM Base2 Protocol (provided by MockgEfiSmmBase2ProtocolGuid)
  //
  if (gBS != NULL) {
    Status = gBS->LocateProtocol (
                    &gEfiSmmBase2ProtocolGuid,
                    NULL,
                    (VOID **)&SmmBase2
                    );
    if (!EFI_ERROR (Status) && (SmmBase2 != NULL)) {
      //
      // Get the SMST location — same call the real SmmServicesTableLib makes
      //
      Status = SmmBase2->GetSmstLocation (SmmBase2, &Smst);
      if (!EFI_ERROR (Status) && (Smst != NULL)) {
        gSmst = Smst;
        gMmst = (EFI_MM_SYSTEM_TABLE *)Smst;
        DEBUG ((DEBUG_INFO, "SmmServicesTableLibConstructor: gSmst=%p (via SmmBase2)\n", gSmst));
        return RETURN_SUCCESS;
      }
    }
  }

  //
  // Fallback: direct assignment if SmmBase2 protocol not available.
  // This handles edge cases where the mock isn't linked (e.g., simple tests).
  //
  gSmst = &gSmmCoreSmst;
  gMmst = (EFI_MM_SYSTEM_TABLE *)&gSmmCoreSmst;
  DEBUG ((DEBUG_INFO, "SmmServicesTableLibConstructor: gSmst=%p (fallback)\n", gSmst));
  return RETURN_SUCCESS;
}

/**
  Indicate whether the driver is currently executing in SMM.

  The host environment always simulates an SMM context so this
  unconditionally returns TRUE. Required by SmmServicesTableLib.h.

  @retval TRUE   Always — we are simulating SMM.
**/
BOOLEAN
EFIAPI
InSmm (
  VOID
  )
{
  return TRUE;
}

/**
  Allocate pages of memory.

  Host implementation: uses malloc(). Type and MemoryType are ignored —
  all allocations come from the host heap. This is deliberate for fuzzing:
  ASan/MSan can instrument heap allocations for bug detection.

  @param[in]  Type           Ignored (AllocateAnyPages/AllocateMaxAddress/AllocateAddress).
  @param[in]  MemoryType     Ignored.
  @param[in]  NumberOfPages  Number of 4KB pages to allocate.
  @param[out] Memory         Receives the allocation address.

  @retval EFI_SUCCESS            Allocation succeeded.
  @retval EFI_INVALID_PARAMETER  NumberOfPages is 0 or exceeds representable range.
  @retval EFI_OUT_OF_RESOURCES   malloc() failed.
**/
EFI_STATUS
EFIAPI
SmmAllocatePages (
  IN  EFI_ALLOCATE_TYPE     Type,
  IN  EFI_MEMORY_TYPE       MemoryType,
  IN  UINTN                 NumberOfPages,
  OUT EFI_PHYSICAL_ADDRESS  *Memory
  )
{
  VOID *Buffer;

  if ((NumberOfPages == 0) ||
      (NumberOfPages > RShiftU64 ((UINTN)-1, EFI_PAGE_SHIFT))) {
    return EFI_INVALID_PARAMETER;
  }

  Buffer = malloc (EFI_PAGES_TO_SIZE(NumberOfPages));
  if (Buffer == NULL) {
    return EFI_OUT_OF_RESOURCES;
  }
  *Memory = (UINTN)Buffer;
  return EFI_SUCCESS;
}

/**
  Free previously allocated pages.

  Host implementation: calls free(). NumberOfPages is ignored since
  glibc free() tracks allocation size internally.

  @param[in] Memory         Base address from SmmAllocatePages.
  @param[in] NumberOfPages  Ignored.

  @retval EFI_SUCCESS  Always succeeds.
**/
EFI_STATUS
EFIAPI
SmmFreePages (
  IN EFI_PHYSICAL_ADDRESS  Memory,
  IN UINTN                 NumberOfPages
  )
{
  free ((VOID *)(UINTN)Memory);
  return EFI_SUCCESS;
}

/**
  Allocate pool memory.

  Host implementation: uses malloc(). PoolType is ignored.

  @param[in]  PoolType  Ignored.
  @param[in]  Size      Bytes to allocate.
  @param[out] Buffer    Receives the allocation pointer.

  @retval EFI_SUCCESS            Allocation succeeded.
  @retval EFI_INVALID_PARAMETER  Buffer is NULL.
  @retval EFI_OUT_OF_RESOURCES   malloc() failed.
**/
EFI_STATUS
EFIAPI
SmmAllocatePool (
  IN EFI_MEMORY_TYPE  PoolType,
  IN UINTN            Size,
  OUT VOID            **Buffer
  )
{
  if (Buffer == NULL) {
    return EFI_INVALID_PARAMETER;
  }
  *Buffer = malloc (Size);
  if (*Buffer == NULL) {
    return EFI_OUT_OF_RESOURCES;
  }
  return EFI_SUCCESS;
}

/**
  Free pool memory.

  Host implementation: calls free().

  @param[in] Buffer  Pointer from SmmAllocatePool.

  @retval EFI_SUCCESS            Buffer freed.
  @retval EFI_INVALID_PARAMETER  Buffer is NULL.
**/
EFI_STATUS
EFIAPI
SmmFreePool (
  IN VOID  *Buffer
  )
{
  if (Buffer == NULL) {
    return EFI_INVALID_PARAMETER;
  }
  free (Buffer);
  return EFI_SUCCESS;
}

// ========================================================================= //
// SMI Dispatch — ported from edk2/MdeModulePkg/Core/PiSmmCore/Smi.c        //
//                                                                           //
// Provides working SmiHandlerRegister / SmiManage / SmiHandlerUnRegister    //
// so that SMM drivers (e.g., SmmLockBox) can register their handlers and    //
// harnesses can dispatch SMIs via gSmst->SmiManage().                       //
// ========================================================================= //

///
/// Tracks recursive SmiManage() calls so that SmiHandlerUnRegister
/// during dispatch is deferred until the outermost SmiManage returns.
///
STATIC UINTN  mSmiManageCallingDepth = 0;

///
/// Linked list of all non-root SMI_ENTRY nodes (keyed by HandlerType GUID).
///
STATIC LIST_ENTRY  mSmiEntryList = INITIALIZE_LIST_HEAD_VARIABLE (mSmiEntryList);

///
/// Root SMI entry — handlers registered with HandlerType == NULL.
///
STATIC SMI_ENTRY  mRootSmiEntry = {
  SMI_ENTRY_SIGNATURE,
  INITIALIZE_LIST_HEAD_VARIABLE (mRootSmiEntry.AllEntries),
  { 0 },
  INITIALIZE_LIST_HEAD_VARIABLE (mRootSmiEntry.SmiHandlers),
};

/**
  Find (or create) the SMI_ENTRY for the given HandlerType GUID.

  @param[in] HandlerType  GUID of the SMI type to look up.
  @param[in] Create       If TRUE and no entry exists, allocate one.

  @return Pointer to the SMI_ENTRY, or NULL if not found and Create is FALSE.
**/
STATIC
SMI_ENTRY *
SmmCoreFindSmiEntry (
  IN EFI_GUID  *HandlerType,
  IN BOOLEAN   Create
  )
{
  LIST_ENTRY  *Link;
  SMI_ENTRY   *Item;
  SMI_ENTRY   *SmiEntry;

  SmiEntry = NULL;
  for (Link = mSmiEntryList.ForwardLink;
       Link != &mSmiEntryList;
       Link = Link->ForwardLink)
  {
    Item = CR (Link, SMI_ENTRY, AllEntries, SMI_ENTRY_SIGNATURE);
    if (CompareGuid (&Item->HandlerType, HandlerType)) {
      SmiEntry = Item;
      break;
    }
  }

  if ((SmiEntry == NULL) && Create) {
    SmiEntry = AllocatePool (sizeof (SMI_ENTRY));
    if (SmiEntry != NULL) {
      SmiEntry->Signature = SMI_ENTRY_SIGNATURE;
      CopyGuid ((VOID *)&SmiEntry->HandlerType, HandlerType);
      InitializeListHead (&SmiEntry->SmiHandlers);
      InsertTailList (&mSmiEntryList, &SmiEntry->AllEntries);
    }
  }

  return SmiEntry;
}

/**
  Remove an SMI_HANDLER from its list and free it. If the parent SMI_ENTRY
  becomes empty, remove and free that too.

  @param[in] SmiHandler  Handler to remove (must have ToRemove == TRUE).
  @param[in] SmiEntry    Parent entry, or NULL for root handlers.

  @retval TRUE   The parent SmiEntry was also removed.
  @retval FALSE  The parent SmiEntry still has other handlers.
**/
STATIC
BOOLEAN
RemoveSmiHandler (
  IN SMI_HANDLER  *SmiHandler,
  IN SMI_ENTRY    *SmiEntry
  )
{
  RemoveEntryList (&SmiHandler->Link);
  FreePool (SmiHandler);

  if (SmiEntry != NULL) {
    if (IsListEmpty (&SmiEntry->SmiHandlers)) {
      RemoveEntryList (&SmiEntry->AllEntries);
      FreePool (SmiEntry);
      return TRUE;
    }
  }

  return FALSE;
}

/**
  Dispatch an SMI to all handlers registered for the given HandlerType.

  Implements the PI SMM SmiManage() semantics:
  - HandlerType == NULL dispatches to root handlers
  - HandlerType != NULL dispatches to all handlers registered for that GUID
  - A handler returning EFI_SUCCESS or EFI_INTERRUPT_PENDING for a non-root
    type stops further dispatch
  - Deferred handler removal is processed when the outermost SmiManage returns

  @param[in]     HandlerType     GUID of the SMI type, or NULL for root.
  @param[in]     Context         Optional context pointer.
  @param[in,out] CommBuffer      Optional communication buffer.
  @param[in,out] CommBufferSize  Optional size of CommBuffer.

  @retval EFI_SUCCESS                        At least one handler succeeded.
  @retval EFI_NOT_FOUND                      No handlers registered for this type.
  @retval EFI_INTERRUPT_PENDING              Handler returned INTERRUPT_PENDING (non-root).
  @retval EFI_WARN_INTERRUPT_SOURCE_PENDING  All handlers returned this warning.
**/
EFI_STATUS
EFIAPI
SmiManage (
  IN     CONST EFI_GUID           *HandlerType,
  IN     CONST VOID               *Context         OPTIONAL,
  IN OUT VOID                     *CommBuffer      OPTIONAL,
  IN OUT UINTN                    *CommBufferSize  OPTIONAL
  )
{
  LIST_ENTRY   *Link;
  LIST_ENTRY   *Head;
  LIST_ENTRY   *EntryLink;
  SMI_ENTRY    *SmiEntry;
  SMI_HANDLER  *SmiHandler;
  EFI_STATUS   ReturnStatus;
  BOOLEAN      WillReturn;
  EFI_STATUS   Status;

  mSmiManageCallingDepth++;
  WillReturn   = FALSE;
  Status       = EFI_NOT_FOUND;
  ReturnStatus = Status;

  if (HandlerType == NULL) {
    //
    // Root SMI handler
    //
    SmiEntry = &mRootSmiEntry;
  } else {
    //
    // Non-root SMI handler
    //
    SmiEntry = SmmCoreFindSmiEntry ((EFI_GUID *)HandlerType, FALSE);
    if (SmiEntry == NULL) {
      mSmiManageCallingDepth--;
      return Status;
    }
  }

  Head = &SmiEntry->SmiHandlers;

  for (Link = Head->ForwardLink; Link != Head; Link = Link->ForwardLink) {
    SmiHandler = CR (Link, SMI_HANDLER, Link, SMI_HANDLER_SIGNATURE);

    Status = SmiHandler->Handler (
                           (EFI_HANDLE)SmiHandler,
                           Context,
                           CommBuffer,
                           CommBufferSize
                           );

    switch (Status) {
      case EFI_INTERRUPT_PENDING:
        if (HandlerType != NULL) {
          ReturnStatus = EFI_INTERRUPT_PENDING;
          WillReturn   = TRUE;
        } else {
          if (ReturnStatus != EFI_SUCCESS) {
            ReturnStatus = Status;
          }
        }
        break;

      case EFI_SUCCESS:
        if (HandlerType != NULL) {
          WillReturn = TRUE;
        }
        ReturnStatus = EFI_SUCCESS;
        break;

      case EFI_WARN_INTERRUPT_SOURCE_QUIESCED:
        ReturnStatus = EFI_SUCCESS;
        break;

      case EFI_WARN_INTERRUPT_SOURCE_PENDING:
        if (ReturnStatus != EFI_SUCCESS) {
          ReturnStatus = Status;
        }
        break;

      default:
        break;
    }

    if (WillReturn) {
      break;
    }
  }

  mSmiManageCallingDepth--;

  //
  // Deferred removal: process handlers marked ToRemove when outermost dispatch completes
  //
  if (mSmiManageCallingDepth == 0) {
    //
    // Root SMI handlers
    //
    for (Link = GetFirstNode (&mRootSmiEntry.SmiHandlers);
         !IsNull (&mRootSmiEntry.SmiHandlers, Link);
         )
    {
      SmiHandler = CR (Link, SMI_HANDLER, Link, SMI_HANDLER_SIGNATURE);
      Link       = GetNextNode (&mRootSmiEntry.SmiHandlers, Link);
      if (SmiHandler->ToRemove) {
        RemoveSmiHandler (SmiHandler, NULL);
      }
    }

    //
    // Non-root SMI handlers
    //
    for (EntryLink = GetFirstNode (&mSmiEntryList);
         !IsNull (&mSmiEntryList, EntryLink);
         )
    {
      SmiEntry  = CR (EntryLink, SMI_ENTRY, AllEntries, SMI_ENTRY_SIGNATURE);
      EntryLink = GetNextNode (&mSmiEntryList, EntryLink);
      for (Link = GetFirstNode (&SmiEntry->SmiHandlers);
           !IsNull (&SmiEntry->SmiHandlers, Link);
           )
      {
        SmiHandler = CR (Link, SMI_HANDLER, Link, SMI_HANDLER_SIGNATURE);
        Link       = GetNextNode (&SmiEntry->SmiHandlers, Link);
        if (SmiHandler->ToRemove) {
          if (RemoveSmiHandler (SmiHandler, SmiEntry)) {
            break;
          }
        }
      }
    }
  }

  return ReturnStatus;
}

/**
  Register an SMI handler.

  Implements the PI SMM SmiHandlerRegister() semantics:
  - HandlerType == NULL registers a root handler
  - HandlerType != NULL registers under the specific GUID type
  - Returns the SMI_HANDLER pointer as the DispatchHandle

  @param[in]  Handler        Handler entry point.
  @param[in]  HandlerType    GUID for the handler type, or NULL for root.
  @param[out] DispatchHandle Returns a handle for later unregistration.

  @retval EFI_SUCCESS            Handler registered.
  @retval EFI_INVALID_PARAMETER  Handler or DispatchHandle is NULL.
  @retval EFI_OUT_OF_RESOURCES   Memory allocation failed.
**/
EFI_STATUS
EFIAPI
SmiHandlerRegister (
  IN  EFI_SMM_HANDLER_ENTRY_POINT2  Handler,
  IN  CONST EFI_GUID                *HandlerType  OPTIONAL,
  OUT EFI_HANDLE                    *DispatchHandle
  )
{
  SMI_HANDLER  *SmiHandler;
  SMI_ENTRY    *SmiEntry;
  LIST_ENTRY   *List;

  if ((Handler == NULL) || (DispatchHandle == NULL)) {
    return EFI_INVALID_PARAMETER;
  }

  SmiHandler = AllocateZeroPool (sizeof (SMI_HANDLER));
  if (SmiHandler == NULL) {
    return EFI_OUT_OF_RESOURCES;
  }

  SmiHandler->Signature = SMI_HANDLER_SIGNATURE;
  SmiHandler->Handler   = Handler;
  SmiHandler->CallerAddr = 0;
  SmiHandler->ToRemove  = FALSE;

  if (HandlerType == NULL) {
    SmiEntry = &mRootSmiEntry;
  } else {
    SmiEntry = SmmCoreFindSmiEntry ((EFI_GUID *)HandlerType, TRUE);
    if (SmiEntry == NULL) {
      FreePool (SmiHandler);
      return EFI_OUT_OF_RESOURCES;
    }
  }

  List = &SmiEntry->SmiHandlers;
  SmiHandler->SmiEntry = SmiEntry;
  InsertTailList (List, &SmiHandler->Link);

  *DispatchHandle = (EFI_HANDLE)SmiHandler;
  return EFI_SUCCESS;
}

/**
  Unregister a previously registered SMI handler.

  Implements the PI SMM SmiHandlerUnRegister() semantics:
  - If called during SmiManage() dispatch, marks for deferred removal
  - If called outside dispatch, removes immediately

  @param[in] DispatchHandle  Handle returned by SmiHandlerRegister.

  @retval EFI_SUCCESS            Handler unregistered (or marked for deferred removal).
  @retval EFI_INVALID_PARAMETER  DispatchHandle is NULL or not found.
**/
EFI_STATUS
EFIAPI
SmiHandlerUnRegister (
  IN EFI_HANDLE  DispatchHandle
  )
{
  SMI_HANDLER  *SmiHandler;
  SMI_ENTRY    *SmiEntry;
  LIST_ENTRY   *EntryLink;
  LIST_ENTRY   *HandlerLink;

  if (DispatchHandle == NULL) {
    return EFI_INVALID_PARAMETER;
  }

  //
  // Look for it in root SMI handlers
  //
  SmiHandler = NULL;
  for (HandlerLink = GetFirstNode (&mRootSmiEntry.SmiHandlers);
       !IsNull (&mRootSmiEntry.SmiHandlers, HandlerLink) && ((EFI_HANDLE)SmiHandler != DispatchHandle);
       HandlerLink = GetNextNode (&mRootSmiEntry.SmiHandlers, HandlerLink))
  {
    SmiHandler = CR (HandlerLink, SMI_HANDLER, Link, SMI_HANDLER_SIGNATURE);
  }

  //
  // Look for it in non-root SMI handlers
  //
  for (EntryLink = GetFirstNode (&mSmiEntryList);
       !IsNull (&mSmiEntryList, EntryLink) && ((EFI_HANDLE)SmiHandler != DispatchHandle);
       EntryLink = GetNextNode (&mSmiEntryList, EntryLink))
  {
    SmiEntry = CR (EntryLink, SMI_ENTRY, AllEntries, SMI_ENTRY_SIGNATURE);
    for (HandlerLink = GetFirstNode (&SmiEntry->SmiHandlers);
         !IsNull (&SmiEntry->SmiHandlers, HandlerLink) && ((EFI_HANDLE)SmiHandler != DispatchHandle);
         HandlerLink = GetNextNode (&SmiEntry->SmiHandlers, HandlerLink))
    {
      SmiHandler = CR (HandlerLink, SMI_HANDLER, Link, SMI_HANDLER_SIGNATURE);
    }
  }

  if (SmiHandler == NULL) {
    return EFI_INVALID_PARAMETER;
  }

  SmiHandler->ToRemove = TRUE;

  if (mSmiManageCallingDepth > 0) {
    //
    // Called during SmiManage — defer removal until dispatch completes
    //
    return EFI_SUCCESS;
  }

  SmiEntry = SmiHandler->SmiEntry;
  RemoveSmiHandler (SmiHandler, (SmiEntry == &mRootSmiEntry) ? NULL : SmiEntry);
  return EFI_SUCCESS;
}

/**
  Stub — multiprocessor AP execution is not supported in the host environment.
  Previously this was NULL in the SMST which would crash callers.
  Now returns EFI_UNSUPPORTED safely.

  @retval EFI_UNSUPPORTED  Always.
**/
EFI_STATUS
EFIAPI
SmmStartupThisAp (
  IN EFI_AP_PROCEDURE  Procedure,
  IN UINTN             CpuNumber,
  IN OUT VOID          *ProcArguments OPTIONAL
  )
{
  return EFI_UNSUPPORTED;
}

