/** @file CustomizedDisplayLibStub.c

  Stub implementation of CustomizedDisplayLib for host-based fuzzing.

  All display functions are no-ops.  WaitForKeyStroke returns ENTER on
  each call so that GetUserSelection terminates immediately.  Color
  functions return fixed constants.

  Copyright (c) 2026, HBFAplus Contributors. SPDX-License-Identifier: BSD-2-Clause-Patent
**/

#include <Uefi.h>
#include <Library/BaseLib.h>
#include <Library/DebugLib.h>

//
// Global callback for WaitForKeyStroke — set by harness before calling
// CreatePopup so that GetUserSelection gets fuzz-controlled key input.
// If NULL, returns ENTER immediately.
//
typedef EFI_STATUS (EFIAPI *WAIT_FOR_KEY_CALLBACK)(OUT EFI_INPUT_KEY *Key);
WAIT_FOR_KEY_CALLBACK  gWaitForKeyCallback = NULL;

//
// ---- Color Functions (return fixed EFI attribute bytes) ----
//

UINT8
EFIAPI
GetPopupColor (
  VOID
  )
{
  return EFI_BACKGROUND_BLUE | EFI_WHITE;
}

UINT8
EFIAPI
GetPopupInverseColor (
  VOID
  )
{
  return EFI_BACKGROUND_LIGHTGRAY | EFI_BLACK;
}

UINT8
EFIAPI
GetHighlightTextColor (
  VOID
  )
{
  return EFI_BACKGROUND_BLACK | EFI_WHITE;
}

UINT8
EFIAPI
GetPickListColor (
  VOID
  )
{
  return EFI_BACKGROUND_CYAN | EFI_BLACK;
}

UINT8
EFIAPI
GetArrowColor (
  VOID
  )
{
  return EFI_BACKGROUND_BLACK | EFI_WHITE;
}

UINT8
EFIAPI
GetInfoTextColor (
  VOID
  )
{
  return EFI_BACKGROUND_BLACK | EFI_YELLOW;
}

UINT8
EFIAPI
GetHelpTextColor (
  VOID
  )
{
  return EFI_BACKGROUND_BLACK | EFI_CYAN;
}

UINT8
EFIAPI
GetGrayedTextColor (
  VOID
  )
{
  return EFI_BACKGROUND_BLACK | EFI_DARKGRAY;
}

UINT8
EFIAPI
GetFieldTextColor (
  VOID
  )
{
  return EFI_BACKGROUND_LIGHTGRAY | EFI_BLACK;
}

UINT8
EFIAPI
GetSubTitleTextColor (
  VOID
  )
{
  return EFI_BACKGROUND_BLACK | EFI_BLUE;
}

//
// ---- Print/Clear Stubs (no-ops — nothing to render in host env) ----
//

UINTN
EFIAPI
PrintStringAt (
  IN UINTN   Column,
  IN UINTN   Row,
  IN CHAR16  *String
  )
{
  return (String != NULL) ? StrLen (String) : 0;
}

UINTN
EFIAPI
PrintStringAtWithWidth (
  IN UINTN   Column,
  IN UINTN   Row,
  IN CHAR16  *String,
  IN UINTN   Width
  )
{
  return (String != NULL) ? StrLen (String) : 0;
}

UINTN
EFIAPI
PrintCharAt (
  IN UINTN  Column,
  IN UINTN  Row,
  CHAR16    Character
  )
{
  return 1;
}

VOID
EFIAPI
ClearLines (
  IN UINTN  LeftColumn,
  IN UINTN  RightColumn,
  IN UINTN  TopRow,
  IN UINTN  BottomRow,
  IN UINTN  TextAttribute
  )
{
}

//
// ---- WaitForKeyStroke — delivers fuzz key or ENTER ----
//

EFI_STATUS
WaitForKeyStroke (
  OUT EFI_INPUT_KEY  *Key
  )
{
  if (gWaitForKeyCallback != NULL) {
    return gWaitForKeyCallback (Key);
  }

  //
  // Default: return ENTER to exit GetUserSelection immediately.
  //
  Key->ScanCode    = SCAN_NULL;
  Key->UnicodeChar = CHAR_CARRIAGE_RETURN;
  return EFI_SUCCESS;
}

//
// ---- Form Display Stubs (unused by Popup.c but referenced elsewhere) ----
//

typedef struct _FORM_DISPLAY_ENGINE_FORM      FORM_DISPLAY_ENGINE_FORM;
typedef struct _FORM_DISPLAY_ENGINE_STATEMENT FORM_DISPLAY_ENGINE_STATEMENT;
typedef struct _EFI_SCREEN_DESCRIPTOR        EFI_SCREEN_DESCRIPTOR;

VOID
EFIAPI
ProcessExternedOpcode (
  IN OUT FORM_DISPLAY_ENGINE_FORM  *FormData
  )
{
}

EFI_STATUS
EFIAPI
DisplayPageFrame (
  IN FORM_DISPLAY_ENGINE_FORM  *FormData,
  OUT EFI_SCREEN_DESCRIPTOR    *ScreenForStatement
  )
{
  return EFI_SUCCESS;
}

VOID
EFIAPI
ClearDisplayPage (
  VOID
  )
{
}

VOID
EFIAPI
RefreshKeyHelp (
  IN FORM_DISPLAY_ENGINE_FORM       *FormData,
  IN FORM_DISPLAY_ENGINE_STATEMENT  *Statement,
  IN BOOLEAN                        Selected
  )
{
}

VOID
EFIAPI
UpdateStatusBar (
  IN UINTN    MessageType,
  IN BOOLEAN  State
  )
{
}

VOID
EFIAPI
CreateDialog (
  OUT EFI_INPUT_KEY  *Key  OPTIONAL,
  ...
  )
{
  if (Key != NULL) {
    Key->ScanCode    = SCAN_NULL;
    Key->UnicodeChar = CHAR_CARRIAGE_RETURN;
  }
}

UINTN
EFIAPI
ConfirmDataChange (
  VOID
  )
{
  //
  // BROWSER_ACTION_DISCARD = 1 — don't save, just exit.
  //
  return 1;
}

BOOLEAN
EFIAPI
FormExitPolicy (
  VOID
  )
{
  return TRUE;
}

UINT64
EFIAPI
FormExitTimeout (
  IN FORM_DISPLAY_ENGINE_FORM  *FormData
  )
{
  return 0;
}

VOID
ConfirmSaveFail (
  IN EFI_INPUT_KEY  TimerEvent,
  IN EFI_STRING     ErrorInfo
  )
{
}

EFI_STATUS
EFIAPI
CustomizedDisplayLibConstructor (
  IN EFI_HANDLE        ImageHandle,
  IN EFI_SYSTEM_TABLE  *SystemTable
  )
{
  return EFI_SUCCESS;
}

EFI_STATUS
EFIAPI
CustomizedDisplayLibDestructor (
  IN EFI_HANDLE        ImageHandle,
  IN EFI_SYSTEM_TABLE  *SystemTable
  )
{
  return EFI_SUCCESS;
}
