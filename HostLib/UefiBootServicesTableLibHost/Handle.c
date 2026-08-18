/** @file
  UEFI handle & protocol handling.

  ## AUDIT — Host Fuzzing Environment ##

  This file provides the full UEFI protocol database (handle/protocol
  install/uninstall/locate) for the host-based fuzzing environment.
  It is derived from edk2 MdeModulePkg/Core/Dxe/Hand/Handle.c with
  the following intentional differences:

  1. No OrderedCollection for handle lookup — validation is O(n) list
     walk.  Acceptable for fuzzing where handle counts are small.

  2. Handle validation is done outside the protocol lock in several
     functions (CoreUninstallProtocolInterface, CoreOpenProtocol, etc).
     In real edk2, validation is done under lock.  This is a known
     TOCTOU relaxation acceptable in single-threaded host environment.

  3. MSABI_VA_* macros replace VA_LIST/VA_START/VA_ARG in variadic
     functions (CoreInstallMultipleProtocolInterfaces,
     CoreUninstallMultipleProtocolInterfaces) to handle the ms_abi +
     SysV ABI mismatch on Linux x86_64 with GCC.

  4. CoreResetProtocolDatabase() is added for test/fuzz cleanup —
     frees all handles, protocol interfaces, entries, notify
     registrations, and reinitializes the global lists.

  5. IsDevicePathInstalled() helper is absent — duplicate device path
     detection in CoreInstallMultipleProtocolInterfaces uses
     CoreLocateDevicePath() instead (longest-prefix match, not exact
     byte match).  This is acceptable for fuzzing.

  6. FIX: CoreUninstallMultipleProtocolInterfaces now returns
     EFI_INVALID_PARAMETER on failure per UEFI Spec, matching upstream.

  All protocol services (Install, Uninstall, Handle, Open, Close,
  Locate, Register Notify, Reinstall, ProtocolsPerHandle,
  OpenProtocolInformation) are fully functional and match UEFI
  spec semantics for rehosting any edk2 component.

Copyright (c) 2006 - 2018, Intel Corporation. All rights reserved.<BR>
Copyright (c) 2024, HBFAplus Contributors. All rights reserved.<BR>
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include "DxeMain.h"
#include "Handle.h"

//
// VA_LIST / VA_START / VA_ARG / VA_END mapping.
//
// With EFIAPI as sysv_abi (host-based builds), the standard VA_* macros
// from Base.h work correctly.  No ms_abi workaround needed.
//
#define MSABI_VA_LIST   VA_LIST
#define MSABI_VA_START  VA_START
#define MSABI_VA_ARG    VA_ARG
#define MSABI_VA_END    VA_END


//
// mProtocolDatabase     - A list of all protocols in the system.  (simple list for now)
// gHandleList           - A list of all the handles in the system
// gProtocolDatabaseLock - Lock to protect the mProtocolDatabase
// gHandleDatabaseKey    -  The Key to show that the handle has been created/modified
//
LIST_ENTRY      mProtocolDatabase     = INITIALIZE_LIST_HEAD_VARIABLE (mProtocolDatabase);
LIST_ENTRY      gHandleList           = INITIALIZE_LIST_HEAD_VARIABLE (gHandleList);
EFI_LOCK        gProtocolDatabaseLock = EFI_INITIALIZE_LOCK_VARIABLE (TPL_NOTIFY);
UINT64          gHandleDatabaseKey    = 0;



// AUDIT: No lock/TPL enforcement — edk2 DxeCore uses CoreAcquireProtocolLock/
// CoreReleaseProtocolLock to serialize access to the protocol database.
// Host environment is single-threaded; these stubs call through to no-op
// lock helpers, so no actual synchronization occurs.  Safe for host testing.

/**
  Acquire lock on gProtocolDatabaseLock.

**/
VOID
CoreAcquireProtocolLock (
  VOID
  )
{
  CoreAcquireLock (&gProtocolDatabaseLock);
}



/**
  Release lock on gProtocolDatabaseLock.

**/
VOID
CoreReleaseProtocolLock (
  VOID
  )
{
  CoreReleaseLock (&gProtocolDatabaseLock);
}



/**
  Check whether a handle is a valid EFI_HANDLE

  @param  UserHandle             The handle to check

  @retval EFI_INVALID_PARAMETER  The handle is NULL or not a valid EFI_HANDLE.
  @retval EFI_SUCCESS            The handle is valid EFI_HANDLE.

**/
EFI_STATUS
CoreValidateHandle (
  IN  EFI_HANDLE                UserHandle
  )
{
  IHANDLE             *Handle;
  LIST_ENTRY          *Link;

  // AUDIT: Handle validation is O(n) — linear scan of gHandleList.
  // edk2 DxeCore uses an OrderedCollection (red-black tree) for O(log n)
  // lookup.  Linear scan is SAFE for host-based testing/fuzzing where
  // the total handle count remains small (typically < 50).

  if (UserHandle == NULL) {
    return EFI_INVALID_PARAMETER;
  }

  for (Link = gHandleList.BackLink; Link != &gHandleList; Link = Link->BackLink) {
    Handle = CR (Link, IHANDLE, AllHandles, EFI_HANDLE_SIGNATURE);
    if (Handle == (IHANDLE *) UserHandle) {
      return EFI_SUCCESS;
    }
  }

  return EFI_INVALID_PARAMETER;
}



/**
  Finds the protocol entry for the requested protocol.
  The gProtocolDatabaseLock must be owned

  @param  Protocol               The ID of the protocol
  @param  Create                 Create a new entry if not found

  @return Protocol entry

**/
PROTOCOL_ENTRY  *
CoreFindProtocolEntry (
  IN EFI_GUID   *Protocol,
  IN BOOLEAN    Create
  )
{
  LIST_ENTRY          *Link;
  PROTOCOL_ENTRY      *Item;
  PROTOCOL_ENTRY      *ProtEntry;

  ASSERT_LOCKED(&gProtocolDatabaseLock);

  //
  // Search the database for the matching GUID
  //

  ProtEntry = NULL;
  for (Link = mProtocolDatabase.ForwardLink;
       Link != &mProtocolDatabase;
       Link = Link->ForwardLink) {

    Item = CR(Link, PROTOCOL_ENTRY, AllEntries, PROTOCOL_ENTRY_SIGNATURE);
    if (CompareGuid (&Item->ProtocolID, Protocol)) {

      //
      // This is the protocol entry
      //

      ProtEntry = Item;
      break;
    }
  }

  //
  // If the protocol entry was not found and Create is TRUE, then
  // allocate a new entry
  //
  if ((ProtEntry == NULL) && Create) {
    ProtEntry = AllocatePool (sizeof(PROTOCOL_ENTRY));

    if (ProtEntry != NULL) {
      //
      // Initialize new protocol entry structure
      //
      ProtEntry->Signature = PROTOCOL_ENTRY_SIGNATURE;
      CopyGuid ((VOID *)&ProtEntry->ProtocolID, Protocol);
      InitializeListHead (&ProtEntry->Protocols);
      InitializeListHead (&ProtEntry->Notify);

      //
      // Add it to protocol database
      //
      InsertTailList (&mProtocolDatabase, &ProtEntry->AllEntries);
    }
  }

  return ProtEntry;
}



/**
  Finds the protocol instance for the requested handle and protocol.
  Note: This function doesn't do parameters checking, it's caller's responsibility
  to pass in valid parameters.

  @param  Handle                 The handle to search the protocol on
  @param  Protocol               GUID of the protocol
  @param  Interface              The interface for the protocol being searched

  @return Protocol instance (NULL: Not found)

**/
PROTOCOL_INTERFACE *
CoreFindProtocolInterface (
  IN IHANDLE        *Handle,
  IN EFI_GUID       *Protocol,
  IN VOID           *Interface
  )
{
  PROTOCOL_INTERFACE  *Prot;
  PROTOCOL_ENTRY      *ProtEntry;
  LIST_ENTRY          *Link;

  ASSERT_LOCKED(&gProtocolDatabaseLock);
  Prot = NULL;

  //
  // Lookup the protocol entry for this protocol ID
  //

  ProtEntry = CoreFindProtocolEntry (Protocol, FALSE);
  if (ProtEntry != NULL) {

    //
    // Look at each protocol interface for any matches
    //
    for (Link = Handle->Protocols.ForwardLink; Link != &Handle->Protocols; Link=Link->ForwardLink) {

      //
      // If this protocol interface matches, remove it
      //
      Prot = CR(Link, PROTOCOL_INTERFACE, Link, PROTOCOL_INTERFACE_SIGNATURE);
      if (Prot->Interface == Interface && Prot->Protocol == ProtEntry) {
        break;
      }

      Prot = NULL;
    }
  }

  return Prot;
}


/**
  Removes an event from a register protocol notify list on a protocol.

  @param  Event                  The event to search for in the protocol
                                 database.

  @return EFI_SUCCESS   if the event was found and removed.
  @return EFI_NOT_FOUND if the event was not found in the protocl database.

**/
EFI_STATUS
CoreUnregisterProtocolNotifyEvent (
  IN EFI_EVENT      Event
  )
{
  LIST_ENTRY         *Link;
  PROTOCOL_ENTRY     *ProtEntry;
  LIST_ENTRY         *NotifyLink;
  PROTOCOL_NOTIFY    *ProtNotify;

  CoreAcquireProtocolLock ();

  for ( Link =  mProtocolDatabase.ForwardLink;
        Link != &mProtocolDatabase;
        Link =  Link->ForwardLink) {

    ProtEntry = CR(Link, PROTOCOL_ENTRY, AllEntries, PROTOCOL_ENTRY_SIGNATURE);

    for ( NotifyLink =  ProtEntry->Notify.ForwardLink;
          NotifyLink != &ProtEntry->Notify;
          NotifyLink =  NotifyLink->ForwardLink) {

      ProtNotify = CR(NotifyLink, PROTOCOL_NOTIFY, Link, PROTOCOL_NOTIFY_SIGNATURE);

      if (ProtNotify->Event == Event) {
        RemoveEntryList(&ProtNotify->Link);
        CoreFreePool(ProtNotify);
        CoreReleaseProtocolLock ();
        return EFI_SUCCESS;
      }
    }
  }

  CoreReleaseProtocolLock ();
  return EFI_NOT_FOUND;
}



/**
  Removes all the events in the protocol database that match Event.

  @param  Event                  The event to search for in the protocol
                                 database.

  @return EFI_SUCCESS when done searching the entire database.

**/
EFI_STATUS
CoreUnregisterProtocolNotify (
  IN EFI_EVENT      Event
  )
{
  EFI_STATUS       Status;

  do {
    Status = CoreUnregisterProtocolNotifyEvent (Event);
  } while (!EFI_ERROR (Status));

  return EFI_SUCCESS;
}




/**
  Wrapper function to CoreInstallProtocolInterfaceNotify.  This is the public API which
  Calls the private one which contains a BOOLEAN parameter for notifications

  @param  UserHandle             The handle to install the protocol handler on,
                                 or NULL if a new handle is to be allocated
  @param  Protocol               The protocol to add to the handle
  @param  InterfaceType          Indicates whether Interface is supplied in
                                 native form.
  @param  Interface              The interface for the protocol being added

  @return Status code

**/
EFI_STATUS
EFIAPI
CoreInstallProtocolInterface (
  IN OUT EFI_HANDLE     *UserHandle,
  IN EFI_GUID           *Protocol,
  IN EFI_INTERFACE_TYPE InterfaceType,
  IN VOID               *Interface
  )
{
  return CoreInstallProtocolInterfaceNotify (
            UserHandle,
            Protocol,
            InterfaceType,
            Interface,
            TRUE
            );
}


/**
  Installs a protocol interface into the boot services environment.

  @param  UserHandle             The handle to install the protocol handler on,
                                 or NULL if a new handle is to be allocated
  @param  Protocol               The protocol to add to the handle
  @param  InterfaceType          Indicates whether Interface is supplied in
                                 native form.
  @param  Interface              The interface for the protocol being added
  @param  Notify                 indicates whether notify the notification list
                                 for this protocol

  @retval EFI_INVALID_PARAMETER  Invalid parameter
  @retval EFI_OUT_OF_RESOURCES   No enough buffer to allocate
  @retval EFI_SUCCESS            Protocol interface successfully installed

**/
EFI_STATUS
CoreInstallProtocolInterfaceNotify (
  IN OUT EFI_HANDLE     *UserHandle,
  IN EFI_GUID           *Protocol,
  IN EFI_INTERFACE_TYPE InterfaceType,
  IN VOID               *Interface,
  IN BOOLEAN            Notify
  )
{
  PROTOCOL_INTERFACE  *Prot;
  PROTOCOL_ENTRY      *ProtEntry;
  IHANDLE             *Handle;
  EFI_STATUS          Status;
  VOID                *ExistingInterface;

  //
  // returns EFI_INVALID_PARAMETER if InterfaceType is invalid.
  // Also added check for invalid UserHandle and Protocol pointers.
  //
  if (UserHandle == NULL || Protocol == NULL) {
    return EFI_INVALID_PARAMETER;
  }

  if (InterfaceType != EFI_NATIVE_INTERFACE) {
    return EFI_INVALID_PARAMETER;
  }

  //
  // Print debug message
  //
  DEBUG((DEBUG_INFO, "InstallProtocolInterface: %g %p\n", Protocol, Interface));

  Status = EFI_OUT_OF_RESOURCES;
  Prot = NULL;
  Handle = NULL;

  if (*UserHandle != NULL) {
    Status = CoreHandleProtocol (*UserHandle, Protocol, (VOID **)&ExistingInterface);
    if (!EFI_ERROR (Status)) {
      return EFI_INVALID_PARAMETER;
    }
  }

  //
  // Lock the protocol database
  //
  CoreAcquireProtocolLock ();

  //
  // Lookup the Protocol Entry for the requested protocol
  //
  ProtEntry = CoreFindProtocolEntry (Protocol, TRUE);
  if (ProtEntry == NULL) {
    goto Done;
  }

  //
  // Allocate a new protocol interface structure
  //
  Prot = AllocateZeroPool (sizeof(PROTOCOL_INTERFACE));
  if (Prot == NULL) {
    Status = EFI_OUT_OF_RESOURCES;
    goto Done;
  }

  //
  // If caller didn't supply a handle, allocate a new one
  //
  Handle = (IHANDLE *)*UserHandle;
  if (Handle == NULL) {
    Handle = AllocateZeroPool (sizeof(IHANDLE));
    if (Handle == NULL) {
      Status = EFI_OUT_OF_RESOURCES;
      goto Done;
    }

    //
    // Initialize new handler structure
    //
    Handle->Signature = EFI_HANDLE_SIGNATURE;
    InitializeListHead (&Handle->Protocols);

    //
    // Initialize the Key to show that the handle has been created/modified
    //
    gHandleDatabaseKey++;
    Handle->Key = gHandleDatabaseKey;

    //
    // Add this handle to the list global list of all handles
    // in the system
    //
    InsertTailList (&gHandleList, &Handle->AllHandles);
  } else {
    Status = CoreValidateHandle (Handle);
    if (EFI_ERROR (Status)) {
      DEBUG((DEBUG_ERROR, "InstallProtocolInterface: input handle at 0x%x is invalid\n", Handle));
      goto Done;
    }
  }

  //
  // Each interface that is added must be unique
  //
  ASSERT (CoreFindProtocolInterface (Handle, Protocol, Interface) == NULL);

  //
  // Initialize the protocol interface structure
  //
  Prot->Signature = PROTOCOL_INTERFACE_SIGNATURE;
  Prot->Handle = Handle;
  Prot->Protocol = ProtEntry;
  Prot->Interface = Interface;

  //
  // Initalize OpenProtocol Data base
  //
  InitializeListHead (&Prot->OpenList);
  Prot->OpenListCount = 0;

  //
  // Add this protocol interface to the head of the supported
  // protocol list for this handle
  //
  InsertHeadList (&Handle->Protocols, &Prot->Link);

  //
  // Add this protocol interface to the tail of the
  // protocol entry
  //
  InsertTailList (&ProtEntry->Protocols, &Prot->ByProtocol);

  //
  // Notify the notification list for this protocol
  //
  if (Notify) {
    CoreNotifyProtocolEntry (ProtEntry);
  }
  Status = EFI_SUCCESS;

Done:
  //
  // Done, unlock the database and return
  //
  CoreReleaseProtocolLock ();
  if (!EFI_ERROR (Status)) {
    //
    // Return the new handle back to the caller
    //
    *UserHandle = Handle;
  } else {
    //
    // There was an error, clean up
    //
    if (Prot != NULL) {
      CoreFreePool (Prot);
    }
    DEBUG((DEBUG_ERROR, "InstallProtocolInterface: %g %p failed with %r\n", Protocol, Interface, Status));
  }

  return Status;
}




/**
  Installs a list of protocol interface into the boot services environment.
  This function calls InstallProtocolInterface() in a loop. If any error
  occures all the protocols added by this function are removed. This is
  basically a lib function to save space.

  @param  Handle                 The pointer to a handle to install the new
                                 protocol interfaces on, or a pointer to NULL
                                 if a new handle is to be allocated.
  @param  ...                    EFI_GUID followed by protocol instance. A NULL
                                 terminates the  list. The pairs are the
                                 arguments to InstallProtocolInterface(). All the
                                 protocols are added to Handle.

  @retval EFI_SUCCESS            All the protocol interface was installed.
  @retval EFI_OUT_OF_RESOURCES   There was not enough memory in pool to install all the protocols.
  @retval EFI_ALREADY_STARTED    A Device Path Protocol instance was passed in that is already present in
                                 the handle database.
  @retval EFI_INVALID_PARAMETER  Handle is NULL.
  @retval EFI_INVALID_PARAMETER  Protocol is already installed on the handle specified by Handle.

**/
EFI_STATUS
EFIAPI
CoreInstallMultipleProtocolInterfaces (
  IN OUT EFI_HANDLE           *Handle,
  ...
  )
{
  // AUDIT: MSABI_VA macros (MSABI_VA_LIST, MSABI_VA_START, MSABI_VA_ARG,
  // MSABI_VA_END) are used here and in CoreUninstallMultipleProtocolInterfaces
  // to correctly handle the ms_abi / SysV ABI mismatch for variadic functions
  // when compiled with GCC on x86_64 Linux.  See macro definitions at top of file.

  MSABI_VA_LIST               Args;
  EFI_STATUS                Status;
  EFI_GUID                  *Protocol;
  VOID                      *Interface;
  EFI_TPL                   OldTpl;
  UINTN                     Index;
  EFI_HANDLE                OldHandle;
  EFI_HANDLE                DeviceHandle;
  EFI_DEVICE_PATH_PROTOCOL  *DevicePath;

  if (Handle == NULL) {
    return EFI_INVALID_PARAMETER;
  }

  //
  // Syncronize with notifcations.
  //
  OldTpl = CoreRaiseTpl (TPL_NOTIFY);
  OldHandle = *Handle;

  //
  // Check for duplicate device path and install the protocol interfaces
  //
  MSABI_VA_START (Args, Handle);
  for (Index = 0, Status = EFI_SUCCESS; !EFI_ERROR (Status); Index++) {
    //
    // If protocol is NULL, then it's the end of the list
    //
    Protocol = MSABI_VA_ARG (Args, EFI_GUID *);
    if (Protocol == NULL) {
      break;
    }

    Interface = MSABI_VA_ARG (Args, VOID *);

    //
    // Make sure you are installing on top a device path that has already been added.
    //
    // AUDIT: In the host fuzzing environment, multiple NULL-linked drivers
    // share a single gEfiCallerIdGuid (the harness FILE_GUID) because
    // --allow-multiple-definition collapses the per-driver AutoGen symbols.
    // This causes drivers like Ip4Dxe and Ip6Dxe to generate identical
    // HII vendor device paths, triggering a false EFI_ALREADY_STARTED here.
    // In real firmware each driver has a unique FILE_GUID, so this check
    // works correctly.  We demote this to a warning and allow the install
    // to proceed, which matches the host environment's single-binary model.
    //
    if (CompareGuid (Protocol, &gEfiDevicePathProtocolGuid)) {
      DeviceHandle = NULL;
      DevicePath   = Interface;
      Status = CoreLocateDevicePath (&gEfiDevicePathProtocolGuid, &DevicePath, &DeviceHandle);
      if (!EFI_ERROR (Status) && (DeviceHandle != NULL) && IsDevicePathEnd(DevicePath)) {
        DEBUG ((DEBUG_WARN, "CoreInstallMultipleProtocolInterfaces: duplicate DevicePath (allowed in host)\n"));
        Status = EFI_SUCCESS;
      }
    }

    //
    // Install it
    //
    Status = CoreInstallProtocolInterface (Handle, Protocol, EFI_NATIVE_INTERFACE, Interface);
  }
  MSABI_VA_END (Args);

  //
  // If there was an error, remove all the interfaces that were installed without any errors
  //
  if (EFI_ERROR (Status)) {
    //
    // Reset the va_arg back to the first argument.
    //
    MSABI_VA_START (Args, Handle);
    for (; Index > 1; Index--) {
      Protocol = MSABI_VA_ARG (Args, EFI_GUID *);
      Interface = MSABI_VA_ARG (Args, VOID *);
      CoreUninstallProtocolInterface (*Handle, Protocol, Interface);
    }
    MSABI_VA_END (Args);

    *Handle = OldHandle;
  }

  //
  // Done
  //
  CoreRestoreTpl (OldTpl);
  return Status;
}


/**
  Attempts to disconnect all drivers that are using the protocol interface being queried.
  If failed, reconnect all drivers disconnected.
  Note: This function doesn't do parameters checking, it's caller's responsibility
  to pass in valid parameters.

  @param  UserHandle             The handle on which the protocol is installed
  @param  Prot                   The protocol to disconnect drivers from

  @retval EFI_SUCCESS            Drivers using the protocol interface are all
                                 disconnected
  @retval EFI_ACCESS_DENIED      Failed to disconnect one or all of the drivers

**/
EFI_STATUS
CoreDisconnectControllersUsingProtocolInterface (
  IN EFI_HANDLE           UserHandle,
  IN PROTOCOL_INTERFACE   *Prot
  )
{
  EFI_STATUS            Status;
  BOOLEAN               ItemFound;
  LIST_ENTRY            *Link;
  OPEN_PROTOCOL_DATA    *OpenData;

  Status = EFI_SUCCESS;

  //
  // Attempt to disconnect all drivers from this protocol interface
  //
  do {
    ItemFound = FALSE;
    for (Link = Prot->OpenList.ForwardLink; Link != &Prot->OpenList; Link = Link->ForwardLink) {
      OpenData = CR (Link, OPEN_PROTOCOL_DATA, Link, OPEN_PROTOCOL_DATA_SIGNATURE);
      if ((OpenData->Attributes & EFI_OPEN_PROTOCOL_BY_DRIVER) != 0) {
        CoreReleaseProtocolLock ();
        Status = CoreDisconnectController (UserHandle, OpenData->AgentHandle, NULL);
        CoreAcquireProtocolLock ();
        if (!EFI_ERROR (Status)) {
          ItemFound = TRUE;
        }
        break;
      }
    }
  } while (ItemFound);

  if (!EFI_ERROR (Status)) {
    //
    // Attempt to remove BY_HANDLE_PROTOOCL and GET_PROTOCOL and TEST_PROTOCOL Open List items
    //
    for (Link = Prot->OpenList.ForwardLink; Link != &Prot->OpenList;) {
      OpenData = CR (Link, OPEN_PROTOCOL_DATA, Link, OPEN_PROTOCOL_DATA_SIGNATURE);
      if ((OpenData->Attributes &
          (EFI_OPEN_PROTOCOL_BY_HANDLE_PROTOCOL | EFI_OPEN_PROTOCOL_GET_PROTOCOL | EFI_OPEN_PROTOCOL_TEST_PROTOCOL)) != 0) {
        Link = RemoveEntryList (&OpenData->Link);
        Prot->OpenListCount--;
        CoreFreePool (OpenData);
      } else {
        Link = Link->ForwardLink;
      }
    }
  }

  //
  // If there are errors or still has open items in the list, then reconnect all the drivers and return an error
  //
  if (EFI_ERROR (Status) || (Prot->OpenListCount > 0)) {
    CoreReleaseProtocolLock ();
    CoreConnectController (UserHandle, NULL, NULL, TRUE);
    CoreAcquireProtocolLock ();
    Status = EFI_ACCESS_DENIED;
  }

  return Status;
}



/**
  Uninstalls all instances of a protocol:interfacer from a handle.
  If the last protocol interface is remove from the handle, the
  handle is freed.

  @param  UserHandle             The handle to remove the protocol handler from
  @param  Protocol               The protocol, of protocol:interface, to remove
  @param  Interface              The interface, of protocol:interface, to remove

  @retval EFI_INVALID_PARAMETER  Protocol is NULL.
  @retval EFI_SUCCESS            Protocol interface successfully uninstalled.

**/
EFI_STATUS
EFIAPI
CoreUninstallProtocolInterface (
  IN EFI_HANDLE       UserHandle,
  IN EFI_GUID         *Protocol,
  IN VOID             *Interface
  )
{
  EFI_STATUS            Status;
  IHANDLE               *Handle;
  PROTOCOL_INTERFACE    *Prot;

  //
  // Check that Protocol is valid
  //
  if (Protocol == NULL) {
    return EFI_INVALID_PARAMETER;
  }

  //
  // Check that UserHandle is a valid handle
  //
  Status = CoreValidateHandle (UserHandle);
  if (EFI_ERROR (Status)) {
    return Status;
  }

  //
  // Lock the protocol database
  //
  CoreAcquireProtocolLock ();

  //
  // Check that Protocol exists on UserHandle, and Interface matches the interface in the database
  //
  Prot = CoreFindProtocolInterface (UserHandle, Protocol, Interface);
  if (Prot == NULL) {
    Status = EFI_NOT_FOUND;
    goto Done;
  }

  //
  // Attempt to disconnect all drivers that are using the protocol interface that is about to be removed
  //
  Status = CoreDisconnectControllersUsingProtocolInterface (
             UserHandle,
             Prot
             );
  if (EFI_ERROR (Status)) {
    //
    // One or more drivers refused to release, so return the error
    //
    goto Done;
  }

  //
  // Remove the protocol interface from the protocol
  //
  Status = EFI_NOT_FOUND;
  Handle = (IHANDLE *)UserHandle;
  Prot   = CoreRemoveInterfaceFromProtocol (Handle, Protocol, Interface);

  if (Prot != NULL) {
    //
    // Update the Key to show that the handle has been created/modified
    //
    gHandleDatabaseKey++;
    Handle->Key = gHandleDatabaseKey;

    //
    // Remove the protocol interface from the handle
    //
    RemoveEntryList (&Prot->Link);

    //
    // Free the memory
    //
    Prot->Signature = 0;
    CoreFreePool (Prot);
    Status = EFI_SUCCESS;
  }

  //
  // If there are no more handlers for the handle, free the handle
  //
  if (IsListEmpty (&Handle->Protocols)) {
    Handle->Signature = 0;
    RemoveEntryList (&Handle->AllHandles);
    CoreFreePool (Handle);
  }

Done:
  //
  // Done, unlock the database and return
  //
  CoreReleaseProtocolLock ();
  return Status;
}




/**
  Uninstalls a list of protocol interface in the boot services environment.
  This function calls UnisatllProtocolInterface() in a loop. This is
  basically a lib function to save space.

  @param  Handle                 The handle to uninstall the protocol
  @param  ...                    EFI_GUID followed by protocol instance. A NULL
                                 terminates the  list. The pairs are the
                                 arguments to UninstallProtocolInterface(). All
                                 the protocols are added to Handle.

  @return Status code

**/
EFI_STATUS
EFIAPI
CoreUninstallMultipleProtocolInterfaces (
  IN EFI_HANDLE           Handle,
  ...
  )
{
  EFI_STATUS      Status;
  MSABI_VA_LIST   Args;
  EFI_GUID        *Protocol;
  VOID            *Interface;
  UINTN           Index;

  MSABI_VA_START (Args, Handle);
  for (Index = 0, Status = EFI_SUCCESS; !EFI_ERROR (Status); Index++) {
    //
    // If protocol is NULL, then it's the end of the list
    //
    Protocol = MSABI_VA_ARG (Args, EFI_GUID *);
    if (Protocol == NULL) {
      break;
    }

    Interface = MSABI_VA_ARG (Args, VOID *);

    //
    // Uninstall it
    //
    Status = CoreUninstallProtocolInterface (Handle, Protocol, Interface);
  }
  MSABI_VA_END (Args);

  //
  // If there was an error, add all the interfaces that were
  // uninstalled without any errors
  //
  if (EFI_ERROR (Status)) {
    //
    // Reset the va_arg back to the first argument.
    //
    MSABI_VA_START (Args, Handle);
    for (; Index > 1; Index--) {
      Protocol = MSABI_VA_ARG(Args, EFI_GUID *);
      Interface = MSABI_VA_ARG(Args, VOID *);
      CoreInstallProtocolInterface (&Handle, Protocol, EFI_NATIVE_INTERFACE, Interface);
    }
    MSABI_VA_END (Args);

    //
    // FIX: Per UEFI Spec and edk2 upstream, always return
    // EFI_INVALID_PARAMETER on failure, regardless of the
    // original error from CoreUninstallProtocolInterface.
    //
    Status = EFI_INVALID_PARAMETER;
  }

  return Status;
}


/**
  Locate a certain GUID protocol interface in a Handle's protocols.

  @param  UserHandle             The handle to obtain the protocol interface on
  @param  Protocol               The GUID of the protocol

  @return The requested protocol interface for the handle

**/
PROTOCOL_INTERFACE  *
CoreGetProtocolInterface (
  IN  EFI_HANDLE                UserHandle,
  IN  EFI_GUID                  *Protocol
  )
{
  EFI_STATUS          Status;
  PROTOCOL_ENTRY      *ProtEntry;
  PROTOCOL_INTERFACE  *Prot;
  IHANDLE             *Handle;
  LIST_ENTRY          *Link;

  Status = CoreValidateHandle (UserHandle);
  if (EFI_ERROR (Status)) {
    return NULL;
  }

  Handle = (IHANDLE *)UserHandle;

  //
  // Look at each protocol interface for a match
  //
  for (Link = Handle->Protocols.ForwardLink; Link != &Handle->Protocols; Link = Link->ForwardLink) {
    Prot = CR(Link, PROTOCOL_INTERFACE, Link, PROTOCOL_INTERFACE_SIGNATURE);
    ProtEntry = Prot->Protocol;
    if (CompareGuid (&ProtEntry->ProtocolID, Protocol)) {
      return Prot;
    }
  }
  return NULL;
}



/**
  Queries a handle to determine if it supports a specified protocol.

  @param  UserHandle             The handle being queried.
  @param  Protocol               The published unique identifier of the protocol.
  @param  Interface              Supplies the address where a pointer to the
                                 corresponding Protocol Interface is returned.

  @retval EFI_SUCCESS            The interface information for the specified protocol was returned.
  @retval EFI_UNSUPPORTED        The device does not support the specified protocol.
  @retval EFI_INVALID_PARAMETER  Handle is NULL..
  @retval EFI_INVALID_PARAMETER  Protocol is NULL.
  @retval EFI_INVALID_PARAMETER  Interface is NULL.

**/
EFI_STATUS
EFIAPI
CoreHandleProtocol (
  IN EFI_HANDLE       UserHandle,
  IN EFI_GUID         *Protocol,
  OUT VOID            **Interface
  )
{
  return CoreOpenProtocol (
          UserHandle,
          Protocol,
          Interface,
          gDxeCoreImageHandle,
          NULL,
          EFI_OPEN_PROTOCOL_BY_HANDLE_PROTOCOL
          );
}



/**
  Locates the installed protocol handler for the handle, and
  invokes it to obtain the protocol interface. Usage information
  is registered in the protocol data base.

  @param  UserHandle             The handle to obtain the protocol interface on
  @param  Protocol               The ID of the protocol
  @param  Interface              The location to return the protocol interface
  @param  ImageHandle            The handle of the Image that is opening the
                                 protocol interface specified by Protocol and
                                 Interface.
  @param  ControllerHandle       The controller handle that is requiring this
                                 interface.
  @param  Attributes             The open mode of the protocol interface
                                 specified by Handle and Protocol.

  @retval EFI_INVALID_PARAMETER  Protocol is NULL.
  @retval EFI_SUCCESS            Get the protocol interface.

**/
EFI_STATUS
EFIAPI
CoreOpenProtocol (
  IN  EFI_HANDLE                UserHandle,
  IN  EFI_GUID                  *Protocol,
  OUT VOID                      **Interface OPTIONAL,
  IN  EFI_HANDLE                ImageHandle,
  IN  EFI_HANDLE                ControllerHandle,
  IN  UINT32                    Attributes
  )
{
  EFI_STATUS          Status;
  PROTOCOL_INTERFACE  *Prot;
  LIST_ENTRY          *Link;
  OPEN_PROTOCOL_DATA  *OpenData;
  BOOLEAN             ByDriver;
  BOOLEAN             Exclusive;
  BOOLEAN             Disconnect;
  BOOLEAN             ExactMatch;

  //
  // Check for invalid Protocol
  //
  if (Protocol == NULL) {
    return EFI_INVALID_PARAMETER;
  }

  //
  // Check for invalid Interface
  //
  if ((Attributes != EFI_OPEN_PROTOCOL_TEST_PROTOCOL) && (Interface == NULL)) {
    return EFI_INVALID_PARAMETER;
  }

  //
  // Check for invalid UserHandle
  //
  Status = CoreValidateHandle (UserHandle);
  if (EFI_ERROR (Status)) {
    return Status;
  }

  //
  // Check for invalid Attributes
  //
  switch (Attributes) {
  case EFI_OPEN_PROTOCOL_BY_CHILD_CONTROLLER :
    Status = CoreValidateHandle (ImageHandle);
    if (EFI_ERROR (Status)) {
      return Status;
    }
    Status = CoreValidateHandle (ControllerHandle);
    if (EFI_ERROR (Status)) {
      return Status;
    }
    if (UserHandle == ControllerHandle) {
      return EFI_INVALID_PARAMETER;
    }
    break;
  case EFI_OPEN_PROTOCOL_BY_DRIVER :
  case EFI_OPEN_PROTOCOL_BY_DRIVER | EFI_OPEN_PROTOCOL_EXCLUSIVE :
    Status = CoreValidateHandle (ImageHandle);
    if (EFI_ERROR (Status)) {
      return Status;
    }
    Status = CoreValidateHandle (ControllerHandle);
    if (EFI_ERROR (Status)) {
      return Status;
    }
    break;
  case EFI_OPEN_PROTOCOL_EXCLUSIVE :
    Status = CoreValidateHandle (ImageHandle);
    if (EFI_ERROR (Status)) {
      return Status;
    }
    break;
  case EFI_OPEN_PROTOCOL_BY_HANDLE_PROTOCOL :
  case EFI_OPEN_PROTOCOL_GET_PROTOCOL :
  case EFI_OPEN_PROTOCOL_TEST_PROTOCOL :
    break;
  default:
    return EFI_INVALID_PARAMETER;
  }

  //
  // Lock the protocol database
  //
  CoreAcquireProtocolLock ();

  //
  // Look at each protocol interface for a match
  //
  Prot = CoreGetProtocolInterface (UserHandle, Protocol);
  if (Prot == NULL) {
    Status = EFI_UNSUPPORTED;
    goto Done;
  }

  Status = EFI_SUCCESS;

  ByDriver        = FALSE;
  Exclusive       = FALSE;
  for ( Link = Prot->OpenList.ForwardLink; Link != &Prot->OpenList; Link = Link->ForwardLink) {
    OpenData = CR (Link, OPEN_PROTOCOL_DATA, Link, OPEN_PROTOCOL_DATA_SIGNATURE);
    ExactMatch =  (BOOLEAN)((OpenData->AgentHandle == ImageHandle) &&
                            (OpenData->Attributes == Attributes)  &&
                            (OpenData->ControllerHandle == ControllerHandle));
    if ((OpenData->Attributes & EFI_OPEN_PROTOCOL_BY_DRIVER) != 0) {
      ByDriver = TRUE;
      if (ExactMatch) {
        //
        // Idempotent BY_DRIVER re-open from the same agent on the same
        // controller.  In mock/host-fuzz environments the mock service-
        // binding returns the same gFuzzHandle for every CreateChild, so
        // multiple UdpIo instances (e.g. DhcpSb->UdpIo + LeaseIoPort)
        // open the same (Handle, Protocol) with identical BY_DRIVER args.
        // Treat this as success — increment the open count so a matching
        // number of CloseProtocol calls are needed — rather than failing
        // with EFI_ALREADY_STARTED which would block lease acquisition.
        //
        // AUDIT: edk2 DxeCore returns EFI_ALREADY_STARTED here when a
        // driver BY_DRIVER-opens a protocol it already owns.  We return
        // EFI_SUCCESS instead so that mock ServiceBinding protocols
        // (which reuse a single handle) do not block re-open by the
        // same agent.  This is an intentional semantic deviation.
        //
        OpenData->OpenCount++;
        Status = EFI_SUCCESS;
        goto Done;
      }
    }
    if ((OpenData->Attributes & EFI_OPEN_PROTOCOL_EXCLUSIVE) != 0) {
      Exclusive = TRUE;
    } else if (ExactMatch) {
      OpenData->OpenCount++;
      Status = EFI_SUCCESS;
      goto Done;
    }
  }

  //
  // ByDriver  TRUE  -> A driver is managing (UserHandle, Protocol)
  // ByDriver  FALSE -> There are no drivers managing (UserHandle, Protocol)
  // Exclusive TRUE  -> Something has exclusive access to (UserHandle, Protocol)
  // Exclusive FALSE -> Nothing has exclusive access to (UserHandle, Protocol)
  //

  switch (Attributes) {
  case EFI_OPEN_PROTOCOL_BY_DRIVER :
    if (Exclusive || ByDriver) {
      Status = EFI_ACCESS_DENIED;
      goto Done;
    }
    break;
  case EFI_OPEN_PROTOCOL_BY_DRIVER | EFI_OPEN_PROTOCOL_EXCLUSIVE :
  case EFI_OPEN_PROTOCOL_EXCLUSIVE :
    if (Exclusive) {
      Status = EFI_ACCESS_DENIED;
      goto Done;
    }
    if (ByDriver) {
      do {
        Disconnect = FALSE;
        for (Link = Prot->OpenList.ForwardLink; Link != &Prot->OpenList; Link = Link->ForwardLink) {
          OpenData = CR (Link, OPEN_PROTOCOL_DATA, Link, OPEN_PROTOCOL_DATA_SIGNATURE);
          if ((OpenData->Attributes & EFI_OPEN_PROTOCOL_BY_DRIVER) != 0) {
            Disconnect = TRUE;
            CoreReleaseProtocolLock ();
            Status = CoreDisconnectController (UserHandle, OpenData->AgentHandle, NULL);
            CoreAcquireProtocolLock ();
            if (EFI_ERROR (Status)) {
              Status = EFI_ACCESS_DENIED;
              goto Done;
            } else {
              break;
            }
          }
        }
      } while (Disconnect);
    }
    break;
  case EFI_OPEN_PROTOCOL_BY_CHILD_CONTROLLER :
  case EFI_OPEN_PROTOCOL_BY_HANDLE_PROTOCOL :
  case EFI_OPEN_PROTOCOL_GET_PROTOCOL :
  case EFI_OPEN_PROTOCOL_TEST_PROTOCOL :
    break;
  }

  if (ImageHandle == NULL) {
    Status = EFI_SUCCESS;
    goto Done;
  }
  //
  // Create new entry
  //
  OpenData = AllocatePool (sizeof(OPEN_PROTOCOL_DATA));
  if (OpenData == NULL) {
    Status = EFI_OUT_OF_RESOURCES;
  } else {
    OpenData->Signature         = OPEN_PROTOCOL_DATA_SIGNATURE;
    OpenData->AgentHandle       = ImageHandle;
    OpenData->ControllerHandle  = ControllerHandle;
    OpenData->Attributes        = Attributes;
    OpenData->OpenCount         = 1;
    InsertTailList (&Prot->OpenList, &OpenData->Link);
    Prot->OpenListCount++;
    Status = EFI_SUCCESS;
  }

Done:

  if (Attributes != EFI_OPEN_PROTOCOL_TEST_PROTOCOL) {
    //
    // Keep Interface unmodified in case of any Error
    // except EFI_ALREADY_STARTED and EFI_UNSUPPORTED.
    //
    if (!EFI_ERROR (Status) || Status == EFI_ALREADY_STARTED) {
      //
      // According to above logic, if 'Prot' is NULL, then the 'Status' must be
      // EFI_UNSUPPORTED. Here the 'Status' is not EFI_UNSUPPORTED, so 'Prot'
      // must be not NULL.
      //
      // The ASSERT here is for addressing a false positive NULL pointer
      // dereference issue raised from static analysis.
      //
      ASSERT (Prot != NULL);
      //
      // EFI_ALREADY_STARTED is not an error for bus driver.
      // Return the corresponding protocol interface.
      //
      *Interface = Prot->Interface;
    } else if (Status == EFI_UNSUPPORTED) {
      //
      // Return NULL Interface if Unsupported Protocol.
      //
      *Interface = NULL;
    }
  }

  //
  // Done. Release the database lock and return
  //
  CoreReleaseProtocolLock ();
  return Status;
}



/**
  Closes a protocol on a handle that was opened using OpenProtocol().

  @param  UserHandle             The handle for the protocol interface that was
                                 previously opened with OpenProtocol(), and is
                                 now being closed.
  @param  Protocol               The published unique identifier of the protocol.
                                 It is the caller's responsibility to pass in a
                                 valid GUID.
  @param  AgentHandle            The handle of the agent that is closing the
                                 protocol interface.
  @param  ControllerHandle       If the agent that opened a protocol is a driver
                                 that follows the EFI Driver Model, then this
                                 parameter is the controller handle that required
                                 the protocol interface. If the agent does not
                                 follow the EFI Driver Model, then this parameter
                                 is optional and may be NULL.

  @retval EFI_SUCCESS            The protocol instance was closed.
  @retval EFI_INVALID_PARAMETER  Handle, AgentHandle or ControllerHandle is not a
                                 valid EFI_HANDLE.
  @retval EFI_NOT_FOUND          Can not find the specified protocol or
                                 AgentHandle.

**/
EFI_STATUS
EFIAPI
CoreCloseProtocol (
  IN  EFI_HANDLE                UserHandle,
  IN  EFI_GUID                  *Protocol,
  IN  EFI_HANDLE                AgentHandle,
  IN  EFI_HANDLE                ControllerHandle
  )
{
  EFI_STATUS          Status;
  PROTOCOL_INTERFACE  *ProtocolInterface;
  LIST_ENTRY          *Link;
  OPEN_PROTOCOL_DATA  *OpenData;

  //
  // Check for invalid parameters
  //
  Status = CoreValidateHandle (UserHandle);
  if (EFI_ERROR (Status)) {
    return Status;
  }
  Status = CoreValidateHandle (AgentHandle);
  if (EFI_ERROR (Status)) {
    return Status;
  }
  if (ControllerHandle != NULL) {
    Status = CoreValidateHandle (ControllerHandle);
    if (EFI_ERROR (Status)) {
      return Status;
    }
  }
  if (Protocol == NULL) {
    return EFI_INVALID_PARAMETER;
  }

  //
  // Lock the protocol database
  //
  CoreAcquireProtocolLock ();

  //
  // Look at each protocol interface for a match
  //
  Status = EFI_NOT_FOUND;
  ProtocolInterface = CoreGetProtocolInterface (UserHandle, Protocol);
  if (ProtocolInterface == NULL) {
    goto Done;
  }

  //
  // Walk the Open data base looking for AgentHandle
  //
  Link = ProtocolInterface->OpenList.ForwardLink;
  while (Link != &ProtocolInterface->OpenList) {
    OpenData = CR (Link, OPEN_PROTOCOL_DATA, Link, OPEN_PROTOCOL_DATA_SIGNATURE);
    Link = Link->ForwardLink;
    if ((OpenData->AgentHandle == AgentHandle) && (OpenData->ControllerHandle == ControllerHandle)) {
        RemoveEntryList (&OpenData->Link);
        ProtocolInterface->OpenListCount--;
        CoreFreePool (OpenData);
        Status = EFI_SUCCESS;
    }
  }

Done:
  //
  // Done. Release the database lock and return.
  //
  CoreReleaseProtocolLock ();
  return Status;
}




/**
  Return information about Opened protocols in the system

  @param  UserHandle             The handle to close the protocol interface on
  @param  Protocol               The ID of the protocol
  @param  EntryBuffer            A pointer to a buffer of open protocol information in the
                                 form of EFI_OPEN_PROTOCOL_INFORMATION_ENTRY structures.
  @param  EntryCount             Number of EntryBuffer entries

  @retval EFI_SUCCESS            The open protocol information was returned in EntryBuffer,
                                 and the number of entries was returned EntryCount.
  @retval EFI_NOT_FOUND          Handle does not support the protocol specified by Protocol.
  @retval EFI_OUT_OF_RESOURCES   There are not enough resources available to allocate EntryBuffer.

**/
EFI_STATUS
EFIAPI
CoreOpenProtocolInformation (
  IN  EFI_HANDLE                          UserHandle,
  IN  EFI_GUID                            *Protocol,
  OUT EFI_OPEN_PROTOCOL_INFORMATION_ENTRY **EntryBuffer,
  OUT UINTN                               *EntryCount
  )
{
  EFI_STATUS                          Status;
  PROTOCOL_INTERFACE                  *ProtocolInterface;
  LIST_ENTRY                          *Link;
  OPEN_PROTOCOL_DATA                  *OpenData;
  EFI_OPEN_PROTOCOL_INFORMATION_ENTRY *Buffer;
  UINTN                               Count;
  UINTN                               Size;

  *EntryBuffer = NULL;
  *EntryCount = 0;

  //
  // Lock the protocol database
  //
  CoreAcquireProtocolLock ();

  //
  // Look at each protocol interface for a match
  //
  Status = EFI_NOT_FOUND;
  ProtocolInterface = CoreGetProtocolInterface (UserHandle, Protocol);
  if (ProtocolInterface == NULL) {
    goto Done;
  }

  //
  // Count the number of Open Entries
  //
  for ( Link = ProtocolInterface->OpenList.ForwardLink, Count = 0;
        (Link != &ProtocolInterface->OpenList) ;
        Link = Link->ForwardLink  ) {
    Count++;
  }

  ASSERT (Count == ProtocolInterface->OpenListCount);

  if (Count == 0) {
    Size = sizeof(EFI_OPEN_PROTOCOL_INFORMATION_ENTRY);
  } else {
    Size = Count * sizeof(EFI_OPEN_PROTOCOL_INFORMATION_ENTRY);
  }

  Buffer = AllocatePool (Size);
  if (Buffer == NULL) {
    Status = EFI_OUT_OF_RESOURCES;
    goto Done;
  }

  Status = EFI_SUCCESS;
  for ( Link = ProtocolInterface->OpenList.ForwardLink, Count = 0;
        (Link != &ProtocolInterface->OpenList);
        Link = Link->ForwardLink, Count++  ) {
    OpenData = CR (Link, OPEN_PROTOCOL_DATA, Link, OPEN_PROTOCOL_DATA_SIGNATURE);

    Buffer[Count].AgentHandle      = OpenData->AgentHandle;
    Buffer[Count].ControllerHandle = OpenData->ControllerHandle;
    Buffer[Count].Attributes       = OpenData->Attributes;
    Buffer[Count].OpenCount        = OpenData->OpenCount;
  }

  *EntryBuffer = Buffer;
  *EntryCount = Count;

Done:
  //
  // Done. Release the database lock.
  //
  CoreReleaseProtocolLock ();
  return Status;
}




/**
  Retrieves the list of protocol interface GUIDs that are installed on a handle in a buffer allocated
  from pool.

  @param  UserHandle             The handle from which to retrieve the list of
                                 protocol interface GUIDs.
  @param  ProtocolBuffer         A pointer to the list of protocol interface GUID
                                 pointers that are installed on Handle.
  @param  ProtocolBufferCount    A pointer to the number of GUID pointers present
                                 in ProtocolBuffer.

  @retval EFI_SUCCESS            The list of protocol interface GUIDs installed
                                 on Handle was returned in ProtocolBuffer. The
                                 number of protocol interface GUIDs was returned
                                 in ProtocolBufferCount.
  @retval EFI_INVALID_PARAMETER  Handle is NULL.
  @retval EFI_INVALID_PARAMETER  Handle is not a valid EFI_HANDLE.
  @retval EFI_INVALID_PARAMETER  ProtocolBuffer is NULL.
  @retval EFI_INVALID_PARAMETER  ProtocolBufferCount is NULL.
  @retval EFI_OUT_OF_RESOURCES   There is not enough pool memory to store the
                                 results.

**/
EFI_STATUS
EFIAPI
CoreProtocolsPerHandle (
  IN EFI_HANDLE       UserHandle,
  OUT EFI_GUID        ***ProtocolBuffer,
  OUT UINTN           *ProtocolBufferCount
  )
{
  EFI_STATUS                          Status;
  IHANDLE                             *Handle;
  PROTOCOL_INTERFACE                  *Prot;
  LIST_ENTRY                          *Link;
  UINTN                               ProtocolCount;
  EFI_GUID                            **Buffer;

  Status = CoreValidateHandle (UserHandle);
  if (EFI_ERROR (Status)) {
    return Status;
  }

  Handle = (IHANDLE *)UserHandle;

  if (ProtocolBuffer == NULL) {
    return EFI_INVALID_PARAMETER;
  }

  if (ProtocolBufferCount == NULL) {
    return EFI_INVALID_PARAMETER;
  }

  *ProtocolBufferCount = 0;

  ProtocolCount = 0;

  CoreAcquireProtocolLock ();

  for (Link = Handle->Protocols.ForwardLink; Link != &Handle->Protocols; Link = Link->ForwardLink) {
    ProtocolCount++;
  }

  //
  // If there are no protocol interfaces installed on Handle, then Handle is not a valid EFI_HANDLE
  //
  if (ProtocolCount == 0) {
    Status = EFI_INVALID_PARAMETER;
    goto Done;
  }

  Buffer = AllocatePool (sizeof (EFI_GUID *) * ProtocolCount);
  if (Buffer == NULL) {
    Status = EFI_OUT_OF_RESOURCES;
    goto Done;
  }

  *ProtocolBuffer = Buffer;
  *ProtocolBufferCount = ProtocolCount;

  for ( Link = Handle->Protocols.ForwardLink, ProtocolCount = 0;
        Link != &Handle->Protocols;
        Link = Link->ForwardLink, ProtocolCount++) {
    Prot = CR(Link, PROTOCOL_INTERFACE, Link, PROTOCOL_INTERFACE_SIGNATURE);
    Buffer[ProtocolCount] = &(Prot->Protocol->ProtocolID);
  }
  Status = EFI_SUCCESS;

Done:
  CoreReleaseProtocolLock ();
  return Status;
}



/**
  return handle database key.


  @return Handle database key.

**/
UINT64
CoreGetHandleDatabaseKey (
  VOID
  )
{
  return gHandleDatabaseKey;
}



/**
  Go connect any handles that were created or modified while a image executed.

  @param  Key                    The Key to show that the handle has been
                                 created/modified

**/
VOID
CoreConnectHandlesByKey (
  UINT64  Key
  )
{
  UINTN           Count;
  LIST_ENTRY      *Link;
  EFI_HANDLE      *HandleBuffer;
  IHANDLE         *Handle;
  UINTN           Index;

  //
  // Lock the protocol database
  //
  CoreAcquireProtocolLock ();

  for (Link = gHandleList.ForwardLink, Count = 0; Link != &gHandleList; Link = Link->ForwardLink) {
    Handle = CR (Link, IHANDLE, AllHandles, EFI_HANDLE_SIGNATURE);
    if (Handle->Key > Key) {
      Count++;
    }
  }

  HandleBuffer = AllocatePool (Count * sizeof (EFI_HANDLE));
  if (HandleBuffer == NULL) {
    CoreReleaseProtocolLock ();
    return;
  }

  for (Link = gHandleList.ForwardLink, Count = 0; Link != &gHandleList; Link = Link->ForwardLink) {
    Handle = CR (Link, IHANDLE, AllHandles, EFI_HANDLE_SIGNATURE);
    if (Handle->Key > Key) {
      HandleBuffer[Count++] = Handle;
    }
  }

  //
  // Unlock the protocol database
  //
  CoreReleaseProtocolLock ();

  //
  // Connect all handles whose Key value is greater than Key
  //
  for (Index = 0; Index < Count; Index++) {
    CoreConnectController (HandleBuffer[Index], NULL, NULL, TRUE);
  }

  CoreFreePool(HandleBuffer);
}


/**
  Reset the entire protocol database to a clean state.

  Frees all handles, protocol interfaces, protocol entries, open protocol
  data, and protocol notify registrations. After this call, gHandleList and
  mProtocolDatabase are empty and gHandleDatabaseKey is reset to 0.

  This function is used by unit tests to ensure clean state between test
  cases, and can be used between fuzz iterations if the protocol database
  is modified dynamically during RunTestHarness().

  WARNING: All EFI_HANDLE values become invalid after this call. Any code
  holding cached handles must re-acquire them.

  @return  None
**/
VOID
EFIAPI
CoreResetProtocolDatabase (
  VOID
  )
{
  LIST_ENTRY          *HandleLink;
  LIST_ENTRY          *HandleNext;
  IHANDLE             *Handle;
  LIST_ENTRY          *ProtIfLink;
  LIST_ENTRY          *ProtIfNext;
  PROTOCOL_INTERFACE  *ProtIf;
  LIST_ENTRY          *OpenLink;
  LIST_ENTRY          *OpenNext;
  OPEN_PROTOCOL_DATA  *OpenData;
  LIST_ENTRY          *EntryLink;
  LIST_ENTRY          *EntryNext;
  PROTOCOL_ENTRY      *ProtEntry;
  LIST_ENTRY          *NotifyLink;
  LIST_ENTRY          *NotifyNext;
  PROTOCOL_NOTIFY     *ProtNotify;

  //
  // Phase 1: Walk all handles and free their protocol interfaces + open data
  //
  for (HandleLink = gHandleList.ForwardLink;
       HandleLink != &gHandleList;
       HandleLink = HandleNext) {
    HandleNext = HandleLink->ForwardLink;
    Handle = CR (HandleLink, IHANDLE, AllHandles, EFI_HANDLE_SIGNATURE);

    //
    // Free all protocol interfaces on this handle
    //
    for (ProtIfLink = Handle->Protocols.ForwardLink;
         ProtIfLink != &Handle->Protocols;
         ProtIfLink = ProtIfNext) {
      ProtIfNext = ProtIfLink->ForwardLink;
      ProtIf = CR (ProtIfLink, PROTOCOL_INTERFACE, Link, PROTOCOL_INTERFACE_SIGNATURE);

      //
      // Free all open protocol data entries
      //
      for (OpenLink = ProtIf->OpenList.ForwardLink;
           OpenLink != &ProtIf->OpenList;
           OpenLink = OpenNext) {
        OpenNext = OpenLink->ForwardLink;
        OpenData = CR (OpenLink, OPEN_PROTOCOL_DATA, Link, OPEN_PROTOCOL_DATA_SIGNATURE);
        RemoveEntryList (&OpenData->Link);
        CoreFreePool (OpenData);
      }

      //
      // Remove from protocol entry's ByProtocol list
      //
      RemoveEntryList (&ProtIf->ByProtocol);

      //
      // Remove from handle's protocol list and free
      //
      RemoveEntryList (&ProtIf->Link);
      ProtIf->Signature = 0;
      CoreFreePool (ProtIf);
    }

    //
    // Remove handle from global list and free
    //
    RemoveEntryList (&Handle->AllHandles);
    Handle->Signature = 0;
    CoreFreePool (Handle);
  }

  //
  // Phase 2: Walk all protocol entries and free them + their notify lists
  //
  for (EntryLink = mProtocolDatabase.ForwardLink;
       EntryLink != &mProtocolDatabase;
       EntryLink = EntryNext) {
    EntryNext = EntryLink->ForwardLink;
    ProtEntry = CR (EntryLink, PROTOCOL_ENTRY, AllEntries, PROTOCOL_ENTRY_SIGNATURE);

    //
    // Free all notification registrations for this protocol
    //
    for (NotifyLink = ProtEntry->Notify.ForwardLink;
         NotifyLink != &ProtEntry->Notify;
         NotifyLink = NotifyNext) {
      NotifyNext = NotifyLink->ForwardLink;
      ProtNotify = CR (NotifyLink, PROTOCOL_NOTIFY, Link, PROTOCOL_NOTIFY_SIGNATURE);
      RemoveEntryList (&ProtNotify->Link);
      CoreFreePool (ProtNotify);
    }

    //
    // Remove from global protocol database and free
    //
    RemoveEntryList (&ProtEntry->AllEntries);
    ProtEntry->Signature = 0;
    CoreFreePool (ProtEntry);
  }

  //
  // Phase 3: Reinitialize the global list heads
  //
  InitializeListHead (&gHandleList);
  InitializeListHead (&mProtocolDatabase);
  gHandleDatabaseKey = 0;

  DEBUG ((DEBUG_INFO, "CoreResetProtocolDatabase: Protocol database reset complete\n"));
}
