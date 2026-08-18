/** @file UefiBootManagerLibNull.c

  Null stub for UefiBootManagerLib — all functions return harmless defaults.
  Used by harnesses linking drivers that reference UefiBootManagerLib
  (e.g., HttpBootDxe config form) but never exercise boot manager APIs.

  Signatures copied verbatim from MdeModulePkg/Include/Library/UefiBootManagerLib.h.

  Copyright (c) 2026, TianoShield Contributors.
  SPDX-License-Identifier: BSD-2-Clause-Patent
**/

#include <Uefi.h>
#include <Library/UefiBootManagerLib.h>

EFI_BOOT_MANAGER_LOAD_OPTION *
EFIAPI
EfiBootManagerGetLoadOptions (
  OUT UINTN                             *LoadOptionCount,
  IN EFI_BOOT_MANAGER_LOAD_OPTION_TYPE  LoadOptionType
  )
{
  *LoadOptionCount = 0;
  return NULL;
}

EFI_STATUS
EFIAPI
EfiBootManagerFreeLoadOptions (
  IN  EFI_BOOT_MANAGER_LOAD_OPTION  *LoadOptions,
  IN  UINTN                         LoadOptionCount
  )
{
  return EFI_SUCCESS;
}

EFI_STATUS
EFIAPI
EfiBootManagerInitializeLoadOption (
  IN OUT EFI_BOOT_MANAGER_LOAD_OPTION    *Option,
  IN  UINTN                              OptionNumber,
  IN  EFI_BOOT_MANAGER_LOAD_OPTION_TYPE  OptionType,
  IN  UINT32                             Attributes,
  IN  CHAR16                             *Description,
  IN  EFI_DEVICE_PATH_PROTOCOL           *FilePath,
  IN  UINT8                              *OptionalData,
  IN  UINT32                             OptionalDataSize
  )
{
  return EFI_SUCCESS;
}

EFI_STATUS
EFIAPI
EfiBootManagerFreeLoadOption (
  IN  EFI_BOOT_MANAGER_LOAD_OPTION  *LoadOption
  )
{
  return EFI_SUCCESS;
}

EFI_STATUS
EFIAPI
EfiBootManagerVariableToLoadOption (
  IN CHAR16                            *VariableName,
  IN OUT EFI_BOOT_MANAGER_LOAD_OPTION  *LoadOption
  )
{
  return EFI_NOT_FOUND;
}

EFI_STATUS
EFIAPI
EfiBootManagerLoadOptionToVariable (
  IN CONST EFI_BOOT_MANAGER_LOAD_OPTION  *LoadOption
  )
{
  return EFI_SUCCESS;
}

EFI_STATUS
EFIAPI
EfiBootManagerAddLoadOptionVariable (
  IN OUT EFI_BOOT_MANAGER_LOAD_OPTION  *Option,
  IN     UINTN                         Position
  )
{
  return EFI_SUCCESS;
}

EFI_STATUS
EFIAPI
EfiBootManagerDeleteLoadOptionVariable (
  IN UINTN                              OptionNumber,
  IN EFI_BOOT_MANAGER_LOAD_OPTION_TYPE  OptionType
  )
{
  return EFI_SUCCESS;
}

VOID
EFIAPI
EfiBootManagerSortLoadOptionVariable (
  IN EFI_BOOT_MANAGER_LOAD_OPTION_TYPE  OptionType,
  IN SORT_COMPARE                       CompareFunction
  )
{
}

INTN
EFIAPI
EfiBootManagerFindLoadOption (
  IN CONST EFI_BOOT_MANAGER_LOAD_OPTION  *Key,
  IN CONST EFI_BOOT_MANAGER_LOAD_OPTION  *Array,
  IN UINTN                               Count
  )
{
  return -1;
}

EFI_STATUS
EFIAPI
EfiBootManagerStartHotkeyService (
  IN EFI_EVENT  *HotkeyTriggered
  )
{
  return EFI_SUCCESS;
}

EFI_STATUS
EFIAPI
EfiBootManagerAddKeyOptionVariable (
  OUT EFI_BOOT_MANAGER_KEY_OPTION  *AddedOption    OPTIONAL,
  IN UINT16                        BootOptionNumber,
  IN UINT32                        Modifier,
  ...
  )
{
  return EFI_SUCCESS;
}

EFI_STATUS
EFIAPI
EfiBootManagerDeleteKeyOptionVariable (
  IN EFI_BOOT_MANAGER_KEY_OPTION  *DeletedOption  OPTIONAL,
  IN UINT32                       Modifier,
  ...
  )
{
  return EFI_SUCCESS;
}

EFI_STATUS
EFIAPI
EfiBootManagerRegisterContinueKeyOption (
  IN UINT32  Modifier,
  ...
  )
{
  return EFI_SUCCESS;
}

VOID
EFIAPI
EfiBootManagerHotkeyBoot (
  VOID
  )
{
}

VOID
EFIAPI
EfiBootManagerRefreshAllBootOption (
  VOID
  )
{
}

VOID
EFIAPI
EfiBootManagerBoot (
  IN  EFI_BOOT_MANAGER_LOAD_OPTION  *BootOption
  )
{
}

EFI_STATUS
EFIAPI
EfiBootManagerGetBootManagerMenu (
  EFI_BOOT_MANAGER_LOAD_OPTION  *BootOption
  )
{
  return EFI_NOT_FOUND;
}

EFI_DEVICE_PATH_PROTOCOL *
EFIAPI
EfiBootManagerGetNextLoadOptionDevicePath (
  IN  EFI_DEVICE_PATH_PROTOCOL  *FilePath,
  IN  EFI_DEVICE_PATH_PROTOCOL  *FullPath
  )
{
  return NULL;
}

VOID *
EFIAPI
EfiBootManagerGetLoadOptionBuffer (
  IN  EFI_DEVICE_PATH_PROTOCOL  *FilePath,
  OUT EFI_DEVICE_PATH_PROTOCOL  **FullPath,
  OUT UINTN                     *FileSize
  )
{
  return NULL;
}

VOID
EFIAPI
EfiBootManagerRegisterLegacyBootSupport (
  EFI_BOOT_MANAGER_REFRESH_LEGACY_BOOT_OPTION  RefreshLegacyBootOption,
  EFI_BOOT_MANAGER_LEGACY_BOOT                 LegacyBoot
  )
{
}

EFI_STATUS
EFIAPI
EfiBootManagerRegisterBootDescriptionHandler (
  IN EFI_BOOT_MANAGER_BOOT_DESCRIPTION_HANDLER  Handler
  )
{
  return EFI_SUCCESS;
}

VOID
EFIAPI
EfiBootManagerConnectAll (
  VOID
  )
{
}

EFI_STATUS
EFIAPI
EfiBootManagerConnectDevicePath (
  IN  EFI_DEVICE_PATH_PROTOCOL  *DevicePathToConnect,
  OUT EFI_HANDLE                *MatchingHandle          OPTIONAL
  )
{
  return EFI_NOT_FOUND;
}

VOID
EFIAPI
EfiBootManagerDisconnectAll (
  VOID
  )
{
}

EFI_STATUS
EFIAPI
EfiBootManagerConnectAllDefaultConsoles (
  VOID
  )
{
  return EFI_SUCCESS;
}

EFI_STATUS
EFIAPI
EfiBootManagerUpdateConsoleVariable (
  IN  CONSOLE_TYPE              ConsoleType,
  IN  EFI_DEVICE_PATH_PROTOCOL  *CustomizedConDevicePath,
  IN  EFI_DEVICE_PATH_PROTOCOL  *ExclusiveDevicePath
  )
{
  return EFI_SUCCESS;
}

EFI_STATUS
EFIAPI
EfiBootManagerConnectConsoleVariable (
  IN  CONSOLE_TYPE  ConsoleType
  )
{
  return EFI_SUCCESS;
}

EFI_DEVICE_PATH_PROTOCOL *
EFIAPI
EfiBootManagerGetGopDevicePath (
  IN  EFI_HANDLE  VideoController
  )
{
  return NULL;
}

EFI_STATUS
EFIAPI
EfiBootManagerConnectVideoController (
  EFI_HANDLE  VideoController  OPTIONAL
  )
{
  return EFI_NOT_FOUND;
}

EFI_BOOT_MANAGER_DRIVER_HEALTH_INFO *
EFIAPI
EfiBootManagerGetDriverHealthInfo (
  UINTN  *Count
  )
{
  *Count = 0;
  return NULL;
}

EFI_STATUS
EFIAPI
EfiBootManagerFreeDriverHealthInfo (
  EFI_BOOT_MANAGER_DRIVER_HEALTH_INFO  *DriverHealthInfo,
  UINTN                                Count
  )
{
  return EFI_SUCCESS;
}

EFI_STATUS
EFIAPI
EfiBootManagerProcessLoadOption (
  EFI_BOOT_MANAGER_LOAD_OPTION  *LoadOption
  )
{
  return EFI_SUCCESS;
}

BOOLEAN
EFIAPI
EfiBootManagerIsValidLoadOptionVariableName (
  IN CHAR16                              *VariableName,
  OUT EFI_BOOT_MANAGER_LOAD_OPTION_TYPE  *OptionType   OPTIONAL,
  OUT UINT16                             *OptionNumber OPTIONAL
  )
{
  return FALSE;
}

EFI_STATUS
EFIAPI
EfiBootManagerDispatchDeferredImages (
  VOID
  )
{
  return EFI_SUCCESS;
}
