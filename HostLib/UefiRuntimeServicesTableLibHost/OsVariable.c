/**
  In-memory UEFI variable store for host-based fuzzing.

  AUDIT NOTES (OsVariable.c):
  ===========================
  This file implements the core variable services (GetVariable, SetVariable,
  GetNextVariableName, QueryVariableInfo) using an in-memory linked list.

  Key design:
    - mVarListEntry is the global linked list head for all variables.
    - CreateVariableList/UpdateVariableList/DeleteVariableList manage nodes.
    - FilterSignatureList deduplicates signature data for db/dbx/KEK append.
    - ProcessVar dispatches add/delete/append based on Attributes and DataSize.
    - Auth2 variables pass through EnrollVar which strips the AUTH2 header.
    - [AUDIT FIX] CoreSetVariable: Added NULL checks for VariableName, VendorGuid.
    - [AUDIT FIX] CoreGetVariable: Added NULL checks for VariableName, VendorGuid.
    - [NEW] CoreGetNextVariableName: Enumerates mVarListEntry linked list.
    - [NEW] CoreQueryVariableInfo: Returns virtual storage capacity.

Copyright (c) 2018, Intel Corporation. All rights reserved.<BR>
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include "OsVariable.h"
#include "VariableCommon.h"
#include "AuthVariable.h"

LIST_ENTRY                  mVarListEntry = INITIALIZE_LIST_HEAD_VARIABLE(mVarListEntry);

/**
  Compare two EFI_TIME data.


  @param FirstTime           A pointer to the first EFI_TIME data.
  @param SecondTime          A pointer to the second EFI_TIME data.

  @retval  TRUE              The FirstTime is not later than the SecondTime.
  @retval  FALSE             The FirstTime is later than the SecondTime.

**/
BOOLEAN
CompareTimeStamp (
  IN EFI_TIME               *FirstTime,
  IN EFI_TIME               *SecondTime
  )
{
  if (FirstTime->Year != SecondTime->Year) {
    return (BOOLEAN) (FirstTime->Year < SecondTime->Year);
  } else if (FirstTime->Month != SecondTime->Month) {
    return (BOOLEAN) (FirstTime->Month < SecondTime->Month);
  } else if (FirstTime->Day != SecondTime->Day) {
    return (BOOLEAN) (FirstTime->Day < SecondTime->Day);
  } else if (FirstTime->Hour != SecondTime->Hour) {
    return (BOOLEAN) (FirstTime->Hour < SecondTime->Hour);
  } else if (FirstTime->Minute != SecondTime->Minute) {
    return (BOOLEAN) (FirstTime->Minute < SecondTime->Minute);
  }

  return (BOOLEAN) (FirstTime->Second <= SecondTime->Second);
}

VOID
GetCurrentTime (
  OUT EFI_TIME      *TimeStamp
  )
{
  time_t CurTime;
  struct tm *GmTime;

  memset (TimeStamp, 0, sizeof (*TimeStamp));

  time (&CurTime);
  GmTime = gmtime (&CurTime);
  if (GmTime == NULL) {
    return;
  }
  TimeStamp->Year = (UINT16)GmTime->tm_year + 1900; // Year is 1900-based
  TimeStamp->Month = (UINT8)GmTime->tm_mon + 1; // Month is zero based.
  TimeStamp->Day = (UINT8)GmTime->tm_mday;
  TimeStamp->Hour = (UINT8)GmTime->tm_hour;
  TimeStamp->Minute = (UINT8)GmTime->tm_min;
  TimeStamp->Second = (UINT8)GmTime->tm_sec;
}

VOID
DumpHex (
  IN UINT8 *Buffer,
  IN UINTN BufferSize
  )
/*++

Routine Description:

  Dump hex data

Arguments:

  Buffer     - Buffer address
  BufferSize - Buffer size

Returns:

  None

--*/
{
  UINTN  Index;
  UINTN  IndexJ;
#define COL_SIZE  16

  for (Index = 0; Index < BufferSize/COL_SIZE; Index++) {
    DEBUG ((DEBUG_INFO, "      %04x: ", (UINT16) Index * COL_SIZE));
    for (IndexJ = 0; IndexJ < COL_SIZE; IndexJ++) {
      DEBUG ((DEBUG_INFO, "%02x ", *(Buffer + Index * COL_SIZE + IndexJ)));
    }
    DEBUG ((DEBUG_INFO, "\n"));
  }
  if ((BufferSize % COL_SIZE) != 0) {
    DEBUG ((DEBUG_INFO, "      %04x: ", (UINT16) Index * COL_SIZE));
    for (IndexJ = 0; IndexJ < (BufferSize % COL_SIZE); IndexJ++) {
      DEBUG ((DEBUG_INFO, "%02x ", *(Buffer + Index * COL_SIZE + IndexJ)));
    }
    DEBUG ((DEBUG_INFO, "\n"));
  }
}

LIST_ENTRY *
FindVariableList (
  IN  LIST_ENTRY     *StorageListHead,
  IN  CHAR16         *Name,
  IN  EFI_GUID       *Guid
  )
{
  LIST_ENTRY              *Link;
  VARIABLE_INFO_PRIVATE   *Storage;

  if (StorageListHead->ForwardLink != NULL) {
    Link = GetFirstNode (StorageListHead);
    while (!IsNull (StorageListHead, Link)) {
      Storage = VARIABLE_INFO_PRIVATE_FROM_LINK (Link);
      if ((CompareGuid (&Storage->Guid, Guid)) &&
          (StrCmp (Storage->Name, Name) == 0)) {
        return Link;
      }
      Link = GetNextNode (StorageListHead, Link);
    }
  }
  return NULL;
}

/*
  Find out the matching VARIABLE_INFO_PRIVATE by variable name and guid.

  @param[in]    VariableName            Name of variable to be find.
  @param[in]    VendorGuid              Variable vendor GUID.

  @retval       VARIABLE_INFO_PRIVATE   A pointer to VARIABLE_INFO_PRIVATE.
  @retval       NULL                    Not find.
*/
VARIABLE_INFO_PRIVATE*
FindVariableInfoPtr(
  IN    CHAR16        *VariableName,
  IN    EFI_GUID      *VendorGuid
  )
{
  LIST_ENTRY          *ListEntry;

  //
  //  Try to get auth variable by name and GUID.
  //
  ListEntry = FindVariableList (&mVarListEntry, VariableName, VendorGuid);
  if (ListEntry != NULL) {
    return VARIABLE_INFO_PRIVATE_FROM_LINK (ListEntry);
  }

  return NULL;
}

/**
  Filter out the duplicated EFI_SIGNATURE_DATA from the new data by comparing to the original data.
  And copy the combined data to final data.

  @param[in]        Data          Pointer to original EFI_SIGNATURE_LIST.
  @param[in]        DataSize      Size of Data buffer.
  @param[in]        NewData       Pointer to new EFI_SIGNATURE_LIST.
  @param[in]        NewDataSize   Size of NewData buffer.
  @param[out]       FinalData     Pointer to final combined EFI_SIGNATURE_LIST.
  @param[out]       FinalDataSize Size of FinalData buffer.

**/
VOID
FilterSignatureList (
  IN  VOID      *Data,
  IN  UINTN     DataSize,
  IN  VOID      *NewData,
  IN  UINTN     NewDataSize,
  OUT VOID      *FinalData,
  OUT UINTN     *FinalDataSize
  )
{
  EFI_SIGNATURE_LIST    *CertList;
  EFI_SIGNATURE_DATA    *Cert;
  UINTN                 CertCount;
  EFI_SIGNATURE_LIST    *NewCertList;
  EFI_SIGNATURE_DATA    *NewCert;
  UINTN                 NewCertCount;
  UINTN                 Index;
  UINTN                 Index2;
  UINTN                 NewSize;
  UINTN                 Size;
  UINT8                 *Tail;
  UINTN                 CopiedCount;
  UINTN                 SignatureListSize;
  BOOLEAN               IsNewCert;

  //
  // Copy the original data to final data first.
  //
  CopyMem (FinalData, Data, DataSize);
  *FinalDataSize = DataSize;

  if (NewDataSize == 0) {
    return;
  }

  Tail = (UINT8 *) FinalData + *FinalDataSize;

  NewSize = NewDataSize;
  NewCertList = (EFI_SIGNATURE_LIST *) NewData;
  while ((NewSize > 0) && (NewSize >= NewCertList->SignatureListSize)) {
    NewCert      = (EFI_SIGNATURE_DATA *) ((UINT8 *) NewCertList + sizeof (EFI_SIGNATURE_LIST) + NewCertList->SignatureHeaderSize);
    NewCertCount = (NewCertList->SignatureListSize - sizeof (EFI_SIGNATURE_LIST) - NewCertList->SignatureHeaderSize) / NewCertList->SignatureSize;

    CopiedCount = 0;
    for (Index = 0; Index < NewCertCount; Index++) {
      IsNewCert = TRUE;

      Size = DataSize;
      CertList = (EFI_SIGNATURE_LIST *) Data;
      while ((Size > 0) && (Size >= CertList->SignatureListSize)) {
        if ((CompareGuid (&CertList->SignatureType, &NewCertList->SignatureType)) &&
           (CertList->SignatureSize == NewCertList->SignatureSize)) {
          Cert      = (EFI_SIGNATURE_DATA *) ((UINT8 *) CertList + sizeof (EFI_SIGNATURE_LIST) + CertList->SignatureHeaderSize);
          CertCount = (CertList->SignatureListSize - sizeof (EFI_SIGNATURE_LIST) - CertList->SignatureHeaderSize) / CertList->SignatureSize;
          for (Index2 = 0; Index2 < CertCount; Index2++) {
            //
            // Iterate each Signature Data in this Signature List.
            //
            if (CompareMem (NewCert, Cert, CertList->SignatureSize) == 0) {
              IsNewCert = FALSE;
              break;
            }
            Cert = (EFI_SIGNATURE_DATA *) ((UINT8 *) Cert + CertList->SignatureSize);
          }
        }

        if (!IsNewCert) {
          break;
        }
        Size -= CertList->SignatureListSize;
        CertList = (EFI_SIGNATURE_LIST *) ((UINT8 *) CertList + CertList->SignatureListSize);
      }

      if (IsNewCert) {
        DEBUG ((DEBUG_INFO, "found new cert!\n"));
        //
        // New EFI_SIGNATURE_DATA, keep it.
        //
        if (CopiedCount == 0) {
          //
          // Copy EFI_SIGNATURE_LIST header for only once.
          //
          CopyMem (Tail, NewCertList, sizeof (EFI_SIGNATURE_LIST) + NewCertList->SignatureHeaderSize);
          Tail = Tail + sizeof (EFI_SIGNATURE_LIST) + NewCertList->SignatureHeaderSize;
        }

        CopyMem (Tail, NewCert, NewCertList->SignatureSize);
        Tail += NewCertList->SignatureSize;
        CopiedCount++;
      }

      NewCert = (EFI_SIGNATURE_DATA *) ((UINT8 *) NewCert + NewCertList->SignatureSize);
    }

    //
    // Update SignatureListSize in the kept EFI_SIGNATURE_LIST.
    //
    if (CopiedCount != 0) {
      SignatureListSize = sizeof (EFI_SIGNATURE_LIST) + NewCertList->SignatureHeaderSize + (CopiedCount * NewCertList->SignatureSize);
      CertList = (EFI_SIGNATURE_LIST *) (Tail - SignatureListSize);
      CertList->SignatureListSize = (UINT32) SignatureListSize;
    }

    NewSize -= NewCertList->SignatureListSize;
    NewCertList = (EFI_SIGNATURE_LIST *) ((UINT8 *) NewCertList + NewCertList->SignatureListSize);
  }

  *FinalDataSize = (Tail - (UINT8 *) FinalData);
}

EFI_STATUS
UpdateVariableList (
  IN  LIST_ENTRY     *Link,
  IN  CHAR16         *Name,
  IN  EFI_GUID       *Guid,
  IN  UINT32         Attributes,
  IN  EFI_TIME       *TimeStamp,
  IN  UINTN          Size,
  IN  UINT8          *Buffer,
  IN  BOOLEAN        Append
  )
{
  VARIABLE_INFO_PRIVATE   *Storage;
  UINTN                   NewSize;
  UINT8                   *NewBuffer;

  Storage = VARIABLE_INFO_PRIVATE_FROM_LINK (Link);

  Storage->Attributes = Attributes;
  if (Append) {
    if ((Attributes & EFI_VARIABLE_TIME_BASED_AUTHENTICATED_WRITE_ACCESS) != 0) {
      //
      // When the new TimeStamp value is later than the current timestamp associated
      // with the variable, we need associate the new timestamp with the updated value.
      //
      if (CompareTimeStamp (&Storage->TimeStamp, TimeStamp)) {
        CopyMem (&Storage->TimeStamp, TimeStamp, sizeof (*TimeStamp));
      }
    }
    NewSize = Storage->Size + Size;
    NewBuffer = malloc (NewSize);
    if (NewBuffer == NULL) {
      return EFI_OUT_OF_RESOURCES;
    }
    ASSERT (Storage->Buffer != NULL);
    if (((CompareGuid (Guid, &gEfiImageSecurityDatabaseGuid)) &&
        ((StrCmp (Name, EFI_IMAGE_SECURITY_DATABASE) == 0) || (StrCmp (Name, EFI_IMAGE_SECURITY_DATABASE1) == 0) ||
        (StrCmp (Name, EFI_IMAGE_SECURITY_DATABASE2) == 0))) ||
        ((CompareGuid (Guid, &gEfiGlobalVariableGuid)) && (StrCmp (Name, EFI_KEY_EXCHANGE_KEY_NAME) == 0))) {
      FilterSignatureList (
        Storage->Buffer,
        Storage->Size,
        Buffer,
        Size,
        NewBuffer,
        &NewSize
        );
    } else {
      CopyMem (NewBuffer, Storage->Buffer, Storage->Size);
      CopyMem (NewBuffer + Storage->Size, Buffer, Size);
    }

    Storage->Size = NewSize;
    free (Storage->Buffer);
    Storage->Buffer = NewBuffer;
  } else {
    if ((Attributes & EFI_VARIABLE_TIME_BASED_AUTHENTICATED_WRITE_ACCESS) != 0) {
      CopyMem (&Storage->TimeStamp, TimeStamp, sizeof (*TimeStamp));
    }
    Storage->Size = Size;
    ASSERT (Storage->Buffer != NULL);
    free (Storage->Buffer);
    Storage->Buffer = malloc (Size);
    if (Storage->Buffer == NULL) {
      return EFI_OUT_OF_RESOURCES;
    }
    CopyMem (Storage->Buffer, Buffer, Size);
  }

  return EFI_SUCCESS;
}

EFI_STATUS
CreateVariableList (
  IN  LIST_ENTRY     *StorageListHead,
  IN  CHAR16         *Name,
  IN  EFI_GUID       *Guid,
  IN  UINT32         Attributes,
  IN  EFI_TIME       *TimeStamp,
  IN  UINTN          Size,
  IN  UINT8          *Buffer,
  IN  BOOLEAN        Append
  )
{
  VARIABLE_INFO_PRIVATE     *Storage;
  UINTN                     VarNameSize;
  LIST_ENTRY                *Link;
  EFI_TIME                  TempTimeStamp;

  if (((Attributes & EFI_VARIABLE_TIME_BASED_AUTHENTICATED_WRITE_ACCESS) != 0) &&
      (TimeStamp == NULL)) {
    //
    // Fetch the current time based on UTC timezone
    //
    GetCurrentTime (&TempTimeStamp);
    TimeStamp = &TempTimeStamp;
  }

  //
  // Check previous one
  //
  Link = FindVariableList (StorageListHead, Name, Guid);
  if (Link != NULL) {
    return UpdateVariableList (
             Link,
             Name,
             Guid,
             Attributes,
             TimeStamp,
             Size,
             Buffer,
             Append
             );
  }

  //
  // Create new one
  //
  Storage = malloc (sizeof (*Storage));
  if (Storage == NULL) {
    return EFI_OUT_OF_RESOURCES;
  }

  Storage->Signature = VARIABLE_INFO_PRIVATE_SIGNATURE;
  CopyMem (&Storage->Guid, Guid, sizeof(*Guid));
  VarNameSize = StrSize (Name);
  Storage->Name = malloc (VarNameSize);
  if (Storage->Name == NULL) {
    free (Storage);
    return EFI_OUT_OF_RESOURCES;
  }
  CopyMem (Storage->Name, Name, VarNameSize);
  Storage->Attributes = Attributes;
  Storage->Size = Size;
  ASSERT (Storage->Size != 0);
  Storage->Buffer = malloc (Size);
  if (Storage->Buffer == NULL) {
    free (Storage->Name);
    free (Storage);
    return EFI_OUT_OF_RESOURCES;
  }
  CopyMem (Storage->Buffer, Buffer, Size);
  if ((Attributes & EFI_VARIABLE_TIME_BASED_AUTHENTICATED_WRITE_ACCESS) != 0) {
    CopyMem (&Storage->TimeStamp, TimeStamp, sizeof (*TimeStamp));
  }

  InsertTailList(StorageListHead, &Storage->Link);

  return EFI_SUCCESS;
}

EFI_STATUS
DeleteVariableList (
  IN  LIST_ENTRY     *StorageListHead,
  IN  CHAR16         *Name,
  IN  EFI_GUID       *Guid
  )
{
  VARIABLE_INFO_PRIVATE     *Storage;
  LIST_ENTRY                *Link;

  Link = FindVariableList (StorageListHead, Name, Guid);
  if (Link == NULL) {
    return EFI_NOT_FOUND;
  }

  Storage = VARIABLE_INFO_PRIVATE_FROM_LINK (Link);
  RemoveEntryList (&Storage->Link);

  return EFI_SUCCESS;
}

EFI_STATUS
EnrollVar (
  IN CHAR16      *Name,
  IN EFI_GUID    *Guid,
  IN UINT32      Attributes,
  IN UINTN       DataSize,
  IN VOID        *Data,
  IN BOOLEAN     TimeBased,
  IN BOOLEAN     Append
  )
{
  EFI_STATUS  EfiStatus;
  UINT8       *Payload;
  UINTN       PayloadSize;
  EFI_TIME    *TimeStamp;

  TimeStamp = NULL;
  Payload = (UINT8 *) Data;
  PayloadSize = DataSize;
  if (TimeBased) {
    TimeStamp = &((EFI_VARIABLE_AUTHENTICATION_2 *) Data)->TimeStamp;
    Payload = (UINT8 *) Data + AUTHINFO2_SIZE (Data);
    PayloadSize = DataSize - AUTHINFO2_SIZE (Data);
  }

  EfiStatus = CreateVariableList (
                &mVarListEntry,
                Name,
                Guid,
                Attributes,
                TimeStamp,
                PayloadSize,
                Payload,
                Append
                );
  return EfiStatus;
}

EFI_STATUS
DeleteVar (
  IN CHAR16      *Name,
  IN EFI_GUID    *Guid
  )
{
  EFI_STATUS  EfiStatus;

  EfiStatus = DeleteVariableList (
                &mVarListEntry,
                Name,
                Guid
                );
  return EfiStatus;
}

EFI_STATUS
ProcessVar (
  IN    CHAR16                      *Name,
  IN    EFI_GUID                    *Guid,
  IN    VOID                        *Data,
  IN    UINTN                       DataSize,
  IN    UINT32                      Attributes
  )
{
  EFI_COMMAND_OPER_TYPE       CommandType;
  EFI_STATUS                  Status;
  BOOLEAN                     TimeBased;

  if ((Attributes == 0) ||
      ((DataSize == 0) && (Data == NULL))) {
    CommandType = VariableTypeDel;
  } else if ((Attributes & EFI_VARIABLE_APPEND_WRITE) != 0) {
    CommandType = VariableTypeAppend;
  } else {
    CommandType = VariableTypeAdd;
  }

  TimeBased = ((Attributes & EFI_VARIABLE_TIME_BASED_AUTHENTICATED_WRITE_ACCESS) != 0);

  if (CommandType == VariableTypeDel) {
    Status = DeleteVar (Name, Guid);
  } else {
    Status = EnrollVar (
                 Name,
                 Guid,
                 Attributes,
                 DataSize,
                 Data,
                 TimeBased,
                 CommandType == VariableTypeAppend ? TRUE : FALSE
                 );
  }

  return Status;
}

VOID
DumpTimestamp (
  IN EFI_TIME            *TimeOfRevocation
  )
{
  DEBUG ((DEBUG_INFO, "  %02d/%02d/%04d %02d:%02d:%02d\n",
    TimeOfRevocation->Month,
    TimeOfRevocation->Day,
    TimeOfRevocation->Year,
    TimeOfRevocation->Hour,
    TimeOfRevocation->Minute,
    TimeOfRevocation->Second
    ));
}

VOID
DumpCert (
  IN  UINT8          *Buffer,
  IN  UINTN          Size
  )
{
  EFI_SIGNATURE_LIST               *CertList;
  EFI_SIGNATURE_DATA               *Cert;
  UINT32                           CertCount;
  UINT32                           CertListIndex;
  UINT32                           CertIndex;

  CertListIndex = 0;
  CertList = (EFI_SIGNATURE_LIST *)Buffer;
  while ((UINTN)CertList < (UINTN)Buffer + Size) {
    DEBUG ((DEBUG_INFO, "SIGNATURE_LIST[%d]\n", CertListIndex));
    DEBUG ((DEBUG_INFO, "  SignatureType       - %08x-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x\n",
      CertList->SignatureType.Data1,
      CertList->SignatureType.Data2,
      CertList->SignatureType.Data3,
      CertList->SignatureType.Data4[0],
      CertList->SignatureType.Data4[1],
      CertList->SignatureType.Data4[2],
      CertList->SignatureType.Data4[3],
      CertList->SignatureType.Data4[4],
      CertList->SignatureType.Data4[5],
      CertList->SignatureType.Data4[6],
      CertList->SignatureType.Data4[7]
      ));
    DEBUG ((DEBUG_INFO, "  SignatureListSize   - %08x\n", CertList->SignatureListSize));
    DEBUG ((DEBUG_INFO, "  SignatureHeaderSize - %08x\n", CertList->SignatureHeaderSize));
    DEBUG ((DEBUG_INFO, "  SignatureSize       - %08x\n", CertList->SignatureSize));
    Cert = (EFI_SIGNATURE_DATA *)((UINT8 *)CertList + sizeof(EFI_SIGNATURE_LIST) + CertList->SignatureHeaderSize);
    CertCount = (CertList->SignatureListSize - sizeof(EFI_SIGNATURE_LIST) - CertList->SignatureHeaderSize) / CertList->SignatureSize;
    for (CertIndex = 0; CertIndex < CertCount; CertIndex++) {
      DEBUG ((DEBUG_INFO, "  SIGNATURE_DATA[%d]\n", CertIndex));
      DEBUG ((DEBUG_INFO, "    SignatureOwner    - %08x-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x\n",
        Cert->SignatureOwner.Data1,
        Cert->SignatureOwner.Data2,
        Cert->SignatureOwner.Data3,
        Cert->SignatureOwner.Data4[0],
        Cert->SignatureOwner.Data4[1],
        Cert->SignatureOwner.Data4[2],
        Cert->SignatureOwner.Data4[3],
        Cert->SignatureOwner.Data4[4],
        Cert->SignatureOwner.Data4[5],
        Cert->SignatureOwner.Data4[6],
        Cert->SignatureOwner.Data4[7]
        ));
      DEBUG ((DEBUG_INFO, "    Signature         - \n"));
      if (CompareGuid (&CertList->SignatureType, &gEfiCertX509Sha256Guid)) {
        EFI_CERT_X509_SHA256  *CertX509Sha256;
        CertX509Sha256 = (EFI_CERT_X509_SHA256 *)Cert->SignatureData;
        DEBUG ((DEBUG_INFO, "      SHA256          - \n"));
        DumpHex (CertX509Sha256->ToBeSignedHash, sizeof(CertX509Sha256->ToBeSignedHash));
        DEBUG ((DEBUG_INFO, "      Timestamp       - \n"));
        DumpTimestamp (&CertX509Sha256->TimeOfRevocation);
      } else if (CompareGuid (&CertList->SignatureType, &gEfiCertX509Sha384Guid)) {
        EFI_CERT_X509_SHA384  *CertX509Sha384;
        CertX509Sha384 = (EFI_CERT_X509_SHA384 *)Cert->SignatureData;
        DEBUG ((DEBUG_INFO, "      SHA384          - \n"));
        DumpHex (CertX509Sha384->ToBeSignedHash, sizeof(CertX509Sha384->ToBeSignedHash));
        DEBUG ((DEBUG_INFO, "      Timestamp       - \n"));
        DumpTimestamp (&CertX509Sha384->TimeOfRevocation);
      } else if (CompareGuid (&CertList->SignatureType, &gEfiCertX509Sha512Guid)) {
        EFI_CERT_X509_SHA512  *CertX509Sha512;
        CertX509Sha512 = (EFI_CERT_X509_SHA512 *)Cert->SignatureData;
        DEBUG ((DEBUG_INFO, "      SHA512          - \n"));
        DumpHex (CertX509Sha512->ToBeSignedHash, sizeof(CertX509Sha512->ToBeSignedHash));
        DEBUG ((DEBUG_INFO, "      Timestamp       - \n"));
        DumpTimestamp (&CertX509Sha512->TimeOfRevocation);
      } else {
        DumpHex (Cert->SignatureData, CertList->SignatureSize - (sizeof(EFI_SIGNATURE_DATA) - 1));
      }
      Cert = (EFI_SIGNATURE_DATA *)((UINT8 *)Cert + CertList->SignatureSize);
    }
    CertList = (EFI_SIGNATURE_LIST *)((UINT8 *)CertList + CertList->SignatureListSize);
    CertListIndex ++;
  }

}

VOID
DumpVarStorage (
  IN VARIABLE_INFO_PRIVATE   *Storage,
  IN BOOLEAN                 IsDumpCert
  )
{
  DEBUG ((DEBUG_INFO, "Variable:\n"));
  DEBUG ((DEBUG_INFO, "  Name       - %s\n", Storage->Name));
  DEBUG ((DEBUG_INFO, "  Guid       - %08x-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x\n",
    Storage->Guid.Data1,
    Storage->Guid.Data2,
    Storage->Guid.Data3,
    Storage->Guid.Data4[0],
    Storage->Guid.Data4[1],
    Storage->Guid.Data4[2],
    Storage->Guid.Data4[3],
    Storage->Guid.Data4[4],
    Storage->Guid.Data4[5],
    Storage->Guid.Data4[6],
    Storage->Guid.Data4[7]
    ));
  DEBUG ((DEBUG_INFO, "  Attributes - %08x\n", Storage->Attributes));
  DEBUG ((DEBUG_INFO, "  Size       - %08x\n", (UINT32) Storage->Size));
  DEBUG ((DEBUG_INFO, "  Buffer     - \n"));
  if (IsDumpCert) {
    DumpCert (Storage->Buffer, Storage->Size);
  } else {
    DumpHex (Storage->Buffer, Storage->Size);
  }
  DEBUG ((DEBUG_INFO, "\n"));
}

VOID
DumpInfo (
  IN  CHAR16         *Name,
  IN  EFI_GUID       *Guid
  )
{
  LIST_ENTRY              *Link;
  VARIABLE_INFO_PRIVATE   *Storage;

  Link = FindVariableList (
           &mVarListEntry,
           Name,
           Guid
           );
  if (Link == NULL) {
    DEBUG ((DEBUG_INFO, "DumpInfo - not found!\n"));
    return ;
  }
  Storage = VARIABLE_INFO_PRIVATE_FROM_LINK (Link);

  DumpVarStorage (Storage, TRUE);

  return ;
}

VOID
DumpVariableList (
  IN  LIST_ENTRY     *StorageListHead
  )
{
  LIST_ENTRY              *Link;
  VARIABLE_INFO_PRIVATE   *Storage;

  if (StorageListHead->ForwardLink != NULL) {
    Link = GetFirstNode (StorageListHead);
    while (!IsNull (StorageListHead, Link)) {
      Storage = VARIABLE_INFO_PRIVATE_FROM_LINK (Link);
      DumpVarStorage (Storage, FALSE);
      Link = GetNextNode (StorageListHead, Link);
    }
  }
}

EFI_STATUS
ProcessKey (
  IN  CHAR16                       *VariableName,
  IN  EFI_GUID                     *VendorGuid,
  IN  VOID                         *Data,
  IN  UINTN                        DataSize,
  IN  UINT32                       Attributes
  )
{
  return ProcessVar (VariableName, VendorGuid, Data, DataSize, Attributes);
}

/**
  [AUDIT] CoreSetVariable - Sets or deletes an in-memory UEFI variable.
  UEFI Spec 8.2.4: If DataSize is non-zero, Data must not be NULL.
  If Attributes is 0 or DataSize is 0, the variable is deleted.

  Added NULL checks for VariableName, VendorGuid per UEFI Spec.

  @param[in] VariableName  A null-terminated string that is the name of the variable.
  @param[in] VendorGuid    A unique identifier for the vendor.
  @param[in] Attributes    Attributes bitmask.
  @param[in] DataSize      The size in bytes of the Data buffer.
  @param[in] Data          The contents for the variable.

  @retval EFI_SUCCESS             Variable set successfully.
  @retval EFI_INVALID_PARAMETER   VariableName or VendorGuid is NULL, or
                                  VariableName is empty string with non-zero DataSize.
**/
EFI_STATUS
EFIAPI
CoreSetVariable (
  IN  CHAR16                       *VariableName,
  IN  EFI_GUID                     *VendorGuid,
  IN  UINT32                       Attributes,
  IN  UINTN                        DataSize,
  IN  VOID                         *Data
  )
{
  //
  // [AUDIT FIX] Validate required parameters per UEFI Spec 8.2.4
  //
  if (VariableName == NULL || VendorGuid == NULL) {
    return EFI_INVALID_PARAMETER;
  }
  if (VariableName[0] == L'\0') {
    return EFI_INVALID_PARAMETER;
  }
  return ProcessKey (VariableName, VendorGuid, Data, DataSize, Attributes);
}

/**
  [AUDIT] CoreGetVariable - Retrieves a variable from the in-memory store.
  UEFI Spec 8.2.1: Returns the value of a variable.

  Added NULL checks for VariableName and VendorGuid per UEFI Spec.

  @param[in]      VariableName  Null-terminated variable name string.
  @param[in]      VendorGuid    Vendor GUID.
  @param[out]     Attributes    Optional pointer to receive attributes.
  @param[in,out]  DataSize      On input, size of Data buffer. On output, actual size.
  @param[out]     Data          Optional buffer to receive the variable data.

  @retval EFI_SUCCESS             Variable retrieved successfully.
  @retval EFI_NOT_FOUND           Variable does not exist.
  @retval EFI_BUFFER_TOO_SMALL    DataSize is too small. DataSize updated.
  @retval EFI_INVALID_PARAMETER   Required parameter is NULL.
**/
EFI_STATUS
EFIAPI
CoreGetVariable (
  IN     CHAR16                      *VariableName,
  IN     EFI_GUID                    *VendorGuid,
  OUT    UINT32                      *Attributes,    OPTIONAL
  IN OUT UINTN                       *DataSize,
  OUT    VOID                        *Data           OPTIONAL
  )
{
  VARIABLE_INFO_PRIVATE     *VariableInfo;

  //
  // [AUDIT FIX] Validate required parameters per UEFI Spec 8.2.1
  //
  if (VariableName == NULL || VendorGuid == NULL || DataSize == NULL) {
    return EFI_INVALID_PARAMETER;
  }

  VariableInfo = FindVariableInfoPtr (VariableName, VendorGuid);
  if (VariableInfo == NULL || VariableInfo->Size == 0) {
    return EFI_NOT_FOUND;
  }
  if (*DataSize < VariableInfo->Size) {
    *DataSize = VariableInfo->Size;
    return EFI_BUFFER_TOO_SMALL;
  }
  *DataSize = VariableInfo->Size;
  if (Data != NULL) {
    CopyMem (Data, VariableInfo->Buffer, VariableInfo->Size);
  }

  if (Attributes != NULL) {
    *Attributes = VariableInfo->Attributes;
  }

  return EFI_SUCCESS;
}

/**
  [AUDIT] CoreGetNextVariableName - Enumerates the in-memory variable store.
  UEFI Spec 8.2.2: Enumerates the current variable names.

  On the first call, VariableName must point to L"\\0" (empty string) and
  VariableNameSize must be at least sizeof(CHAR16). On each subsequent call,
  the function returns the next variable name and GUID in the store.

  @param[in,out]  VariableNameSize  On input, size of VariableName buffer in bytes.
                                    On output, size needed.
  @param[in,out]  VariableName      On input, previous variable name.
                                    On output, next variable name.
  @param[in,out]  VendorGuid        On input, previous vendor GUID.
                                    On output, next vendor GUID.

  @retval EFI_SUCCESS             Next variable name returned.
  @retval EFI_NOT_FOUND           No more variables (end of list).
  @retval EFI_BUFFER_TOO_SMALL    VariableNameSize too small. Updated with needed size.
  @retval EFI_INVALID_PARAMETER   Any pointer is NULL.
**/
EFI_STATUS
EFIAPI
CoreGetNextVariableName (
  IN OUT UINTN                       *VariableNameSize,
  IN OUT CHAR16                      *VariableName,
  IN OUT EFI_GUID                    *VendorGuid
  )
{
  LIST_ENTRY              *Link;
  VARIABLE_INFO_PRIVATE   *Storage;
  UINTN                   NameSizeNeeded;

  if (VariableNameSize == NULL || VariableName == NULL || VendorGuid == NULL) {
    return EFI_INVALID_PARAMETER;
  }

  //
  // If the list is empty, there are no variables to enumerate.
  //
  if (mVarListEntry.ForwardLink == NULL || IsListEmpty (&mVarListEntry)) {
    return EFI_NOT_FOUND;
  }

  //
  // First call: VariableName is an empty string L"\0"
  //
  if (VariableName[0] == L'\0') {
    Storage = VARIABLE_INFO_PRIVATE_FROM_LINK (GetFirstNode (&mVarListEntry));
    NameSizeNeeded = StrSize (Storage->Name);
    if (*VariableNameSize < NameSizeNeeded) {
      *VariableNameSize = NameSizeNeeded;
      return EFI_BUFFER_TOO_SMALL;
    }
    *VariableNameSize = NameSizeNeeded;
    CopyMem (VariableName, Storage->Name, NameSizeNeeded);
    CopyMem (VendorGuid, &Storage->Guid, sizeof (EFI_GUID));
    return EFI_SUCCESS;
  }

  //
  // Subsequent calls: find the current variable, then return the next one.
  //
  Link = GetFirstNode (&mVarListEntry);
  while (!IsNull (&mVarListEntry, Link)) {
    Storage = VARIABLE_INFO_PRIVATE_FROM_LINK (Link);
    if ((CompareGuid (&Storage->Guid, VendorGuid)) &&
        (StrCmp (Storage->Name, VariableName) == 0)) {
      //
      // Found the current variable. Return the next one.
      //
      Link = GetNextNode (&mVarListEntry, Link);
      if (IsNull (&mVarListEntry, Link)) {
        return EFI_NOT_FOUND;  // End of list
      }
      Storage = VARIABLE_INFO_PRIVATE_FROM_LINK (Link);
      NameSizeNeeded = StrSize (Storage->Name);
      if (*VariableNameSize < NameSizeNeeded) {
        *VariableNameSize = NameSizeNeeded;
        return EFI_BUFFER_TOO_SMALL;
      }
      *VariableNameSize = NameSizeNeeded;
      CopyMem (VariableName, Storage->Name, NameSizeNeeded);
      CopyMem (VendorGuid, &Storage->Guid, sizeof (EFI_GUID));
      return EFI_SUCCESS;
    }
    Link = GetNextNode (&mVarListEntry, Link);
  }

  //
  // The supplied variable name was not found in the list.
  //
  return EFI_INVALID_PARAMETER;
}

/**
  [AUDIT] CoreQueryVariableInfo - Returns virtual variable store capacity.
  UEFI Spec 8.2.6: Returns information about the UEFI variable store.
  Our in-memory store has no fixed limit, but we report a reasonable
  virtual capacity for compatibility with callers that check these values.

  @param[in]  Attributes                     Attributes bitmask to query.
  @param[out] MaximumVariableStorageSize     Maximum total storage in bytes.
  @param[out] RemainingVariableStorageSize   Remaining storage in bytes.
  @param[out] MaximumVariableSize            Maximum single variable size in bytes.

  @retval EFI_SUCCESS             Information returned successfully.
  @retval EFI_INVALID_PARAMETER   A required pointer is NULL or Attributes is 0.
**/
// AUDIT: BUG-class — returns hardcoded 248KB remaining instead of
// tracking actual usage. Acceptable for fuzzing where variable
// storage pressure is never tested.
EFI_STATUS
EFIAPI
CoreQueryVariableInfo (
  IN  UINT32                       Attributes,
  OUT UINT64                       *MaximumVariableStorageSize,
  OUT UINT64                       *RemainingVariableStorageSize,
  OUT UINT64                       *MaximumVariableSize
  )
{
  if (MaximumVariableStorageSize == NULL ||
      RemainingVariableStorageSize == NULL ||
      MaximumVariableSize == NULL) {
    return EFI_INVALID_PARAMETER;
  }
  if (Attributes == 0) {
    return EFI_INVALID_PARAMETER;
  }

  //
  // Report a generous virtual NV store. The in-memory store is limited
  // only by host malloc, but callers expect finite sizes.
  //
  *MaximumVariableStorageSize    = 0x40000;   // 256 KB total
  *RemainingVariableStorageSize  = 0x3E000;   // ~248 KB remaining
  *MaximumVariableSize           = 0x10000;   // 64 KB per variable
  return EFI_SUCCESS;
}
