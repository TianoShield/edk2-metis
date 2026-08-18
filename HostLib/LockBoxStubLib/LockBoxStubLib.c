/** @file LockBoxStubLib.c
    Minimal in-memory LockBox library for host-based fuzzing.

    Provides SaveLockBox/UpdateLockBox/RestoreLockBox/SetLockBoxAttributes/
    RestoreAllLockBoxInPlace backed by simple malloc'd storage.  Suitable
    for exercising SmmLockBox handler logic without real SMRAM.

    Copyright (c) 2026, HBFAplus Contributors. All rights reserved.
    SPDX-License-Identifier: BSD-2-Clause-Patent
**/

#include <Uefi.h>
#include <Library/BaseLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/DebugLib.h>
#include <Library/LockBoxLib.h>

#define MAX_LOCK_BOXES  64

typedef struct {
  BOOLEAN   InUse;
  EFI_GUID  Guid;
  VOID      *Buffer;
  UINTN     Length;
  UINT64    Attributes;
} LOCK_BOX_ENTRY;

STATIC LOCK_BOX_ENTRY  mLockBoxes[MAX_LOCK_BOXES];

STATIC
LOCK_BOX_ENTRY *
FindByGuid (
  IN GUID  *Guid
  )
{
  UINTN  Index;

  for (Index = 0; Index < MAX_LOCK_BOXES; Index++) {
    if (mLockBoxes[Index].InUse && CompareGuid (&mLockBoxes[Index].Guid, Guid)) {
      return &mLockBoxes[Index];
    }
  }

  return NULL;
}

STATIC
LOCK_BOX_ENTRY *
FindFreeSlot (
  VOID
  )
{
  UINTN  Index;

  for (Index = 0; Index < MAX_LOCK_BOXES; Index++) {
    if (!mLockBoxes[Index].InUse) {
      return &mLockBoxes[Index];
    }
  }

  return NULL;
}

RETURN_STATUS
EFIAPI
SaveLockBox (
  IN GUID  *Guid,
  IN VOID  *Buffer,
  IN UINTN  Length
  )
{
  LOCK_BOX_ENTRY  *Entry;

  if (Guid == NULL || Buffer == NULL || Length == 0) {
    return RETURN_INVALID_PARAMETER;
  }

  Entry = FindByGuid (Guid);
  if (Entry != NULL) {
    return RETURN_ALREADY_STARTED;
  }

  Entry = FindFreeSlot ();
  if (Entry == NULL) {
    return RETURN_OUT_OF_RESOURCES;
  }

  Entry->Buffer = AllocatePool (Length);
  if (Entry->Buffer == NULL) {
    return RETURN_OUT_OF_RESOURCES;
  }

  CopyMem (Entry->Buffer, Buffer, Length);
  CopyGuid (&Entry->Guid, Guid);
  Entry->Length     = Length;
  Entry->Attributes = 0;
  Entry->InUse      = TRUE;

  return RETURN_SUCCESS;
}

RETURN_STATUS
EFIAPI
SetLockBoxAttributes (
  IN GUID    *Guid,
  IN UINT64   Attributes
  )
{
  LOCK_BOX_ENTRY  *Entry;

  if (Guid == NULL) {
    return RETURN_INVALID_PARAMETER;
  }

  Entry = FindByGuid (Guid);
  if (Entry == NULL) {
    return RETURN_NOT_FOUND;
  }

  Entry->Attributes = Attributes;
  return RETURN_SUCCESS;
}

RETURN_STATUS
EFIAPI
UpdateLockBox (
  IN GUID  *Guid,
  IN UINTN  Offset,
  IN VOID  *Buffer,
  IN UINTN  Length
  )
{
  LOCK_BOX_ENTRY  *Entry;

  if (Guid == NULL || Buffer == NULL) {
    return RETURN_INVALID_PARAMETER;
  }

  Entry = FindByGuid (Guid);
  if (Entry == NULL) {
    return RETURN_NOT_FOUND;
  }

  if (Offset + Length > Entry->Length) {
    return RETURN_BUFFER_TOO_SMALL;
  }

  CopyMem ((UINT8 *)Entry->Buffer + Offset, Buffer, Length);
  return RETURN_SUCCESS;
}

RETURN_STATUS
EFIAPI
RestoreLockBox (
  IN     GUID   *Guid,
  IN     VOID   *Buffer  OPTIONAL,
  IN OUT UINTN  *Length   OPTIONAL
  )
{
  LOCK_BOX_ENTRY  *Entry;

  if (Guid == NULL) {
    return RETURN_INVALID_PARAMETER;
  }

  Entry = FindByGuid (Guid);
  if (Entry == NULL) {
    return RETURN_NOT_FOUND;
  }

  if (Buffer == NULL || Length == NULL) {
    return RETURN_SUCCESS;
  }

  if (*Length < Entry->Length) {
    *Length = Entry->Length;
    return RETURN_BUFFER_TOO_SMALL;
  }

  CopyMem (Buffer, Entry->Buffer, Entry->Length);
  *Length = Entry->Length;
  return RETURN_SUCCESS;
}

RETURN_STATUS
EFIAPI
RestoreAllLockBoxInPlace (
  VOID
  )
{
  return RETURN_SUCCESS;
}
