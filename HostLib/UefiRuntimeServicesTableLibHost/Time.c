/** @file
  Time services for host-based UEFI Runtime Services.

  AUDIT NOTES (Time.c):
  =====================
  - CoreGetTime: Returns the current in-memory time.  Initialized to a
    deterministic value (2025-01-01 00:00:00) for fuzzing reproducibility.
    If CoreSetTime is called, subsequent CoreGetTime calls reflect the
    updated value.  This ensures SetTime/GetTime coherence within a single
    fuzz iteration while keeping the default deterministic.
    Fixed: Returns EFI_INVALID_PARAMETER if Time==NULL per UEFI Spec 8.3.1.
    The Capabilities output is zeroed (resolution=1s, accuracy=0,
    sets-to-zero=FALSE).
  - CoreSetTime: Updates the in-memory time returned by CoreGetTime.
    Validates per UEFI Spec 8.3.2.  Does NOT modify the host system clock.
  - CoreGetWakeupTime: Returns Enabled=FALSE, Pending=FALSE.
    Wakeup timers are not meaningful on a host system.
  - CoreSetWakeupTime: No-op. Returns EFI_SUCCESS.
    Wakeup timers are not meaningful on a host system.

Copyright (c) 2018, Intel Corporation. All rights reserved.<BR>
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <time.h>

#include <Uefi.h>
#include <Library/DebugLib.h>
#include <Library/BaseMemoryLib.h>

//
// In-memory time state.  Initialized to a deterministic default so that
// DUID-LLT timestamps (and any other time-dependent logic) are reproducible
// across fuzzing runs.  CoreSetTime updates this; CoreGetTime reads it.
//
STATIC EFI_TIME mCurrentTime = {
  2025,   // Year
  1,      // Month
  1,      // Day
  0,      // Hour
  0,      // Minute
  0,      // Second
  0,      // Pad1
  0,      // Nanosecond
  0,      // TimeZone
  0,      // Daylight
  0       // Pad2
};

/**
  GetTime — Returns the current in-memory time.

  The default is a deterministic 2025-01-01 00:00:00, essential for
  reproducible fuzzing (DUID-LLT timestamps, elapsed-time calculations).
  If CoreSetTime has been called during this iteration, the updated value
  is returned instead.

  UEFI Spec 8.3.1: If Time is NULL, returns EFI_INVALID_PARAMETER.
  Capabilities is optional and zeroed if provided.

  @param[out] Time          Pointer to receive the current time.
  @param[out] Capabilities  Optional pointer to receive time capabilities.

  @retval EFI_SUCCESS             Time retrieved successfully.
  @retval EFI_INVALID_PARAMETER   Time is NULL.
**/
EFI_STATUS
EFIAPI
CoreGetTime (
  OUT  EFI_TIME                    *Time,
  OUT  EFI_TIME_CAPABILITIES       *Capabilities OPTIONAL
  )
{
  if (Time == NULL) {
    return EFI_INVALID_PARAMETER;
  }

  CopyMem (Time, &mCurrentTime, sizeof (*Time));

  if (Capabilities != NULL) {
    ZeroMem (Capabilities, sizeof (*Capabilities));
  }
  return EFI_SUCCESS;
}

/**
  SetTime — Updates the in-memory time returned by CoreGetTime.

  UEFI Spec 8.3.2: Sets the current local date and time information.
  On the host we update only the in-memory mCurrentTime; the host system
  clock is never modified.  Basic field validation per UEFI Spec Table 38.

  @param[in] Time  Pointer to the time to set.

  @retval EFI_SUCCESS             Time updated.
  @retval EFI_INVALID_PARAMETER   Time is NULL or fields out of range.
**/
EFI_STATUS
EFIAPI
CoreSetTime (
  IN  EFI_TIME                     *Time
  )
{
  if (Time == NULL) {
    return EFI_INVALID_PARAMETER;
  }

  //
  // Basic range check per UEFI Spec Table 38.
  //
  if (Time->Month < 1 || Time->Month > 12 ||
      Time->Day < 1 || Time->Day > 31 ||
      Time->Hour > 23 ||
      Time->Minute > 59 ||
      Time->Second > 59) {
    return EFI_INVALID_PARAMETER;
  }

  CopyMem (&mCurrentTime, Time, sizeof (mCurrentTime));
  return EFI_SUCCESS;
}

/**
  [AUDIT] GetWakeupTime - Returns that wakeup timer is disabled.
  UEFI Spec 8.3.3: Returns the current wakeup alarm clock setting.
  On the host there is no RTC wakeup capability.

  @param[out] Enabled   Indicates if the alarm is enabled.
  @param[out] Pending   Indicates if the alarm signal is pending.
  @param[out] Time      The current alarm setting time.

  @retval EFI_SUCCESS             Values returned successfully.
  @retval EFI_INVALID_PARAMETER   Any pointer is NULL.
**/
EFI_STATUS
EFIAPI
CoreGetWakeupTime (
  OUT BOOLEAN                      *Enabled,
  OUT BOOLEAN                      *Pending,
  OUT EFI_TIME                     *Time
  )
{
  if (Enabled == NULL || Pending == NULL || Time == NULL) {
    return EFI_INVALID_PARAMETER;
  }
  *Enabled = FALSE;
  *Pending = FALSE;
  ZeroMem (Time, sizeof(*Time));
  return EFI_SUCCESS;
}

/**
  [AUDIT] SetWakeupTime - No-op for host-based fuzzing.
  UEFI Spec 8.3.4: Sets the system wakeup alarm clock time.
  No RTC wakeup capability on host.

  @param[in] Enable  Enable or disable the wakeup alarm.
  @param[in] Time    Optional time to set (ignored).

  @retval EFI_SUCCESS  Always (no-op).
**/
EFI_STATUS
EFIAPI
CoreSetWakeupTime (
  IN  BOOLEAN                      Enable,
  IN  EFI_TIME                     *Time   OPTIONAL
  )
{
  //
  // No-op: no RTC wakeup on host.
  //
  return EFI_SUCCESS;
}
