/** @file HostShim.c
    Hardware shims for the host-based fuzzing environment.

    The real DXE Core event/timer/TPL code references several hardware
    protocol pointers and global structures.  In real UEFI firmware these
    are provided by platform DXE drivers (CpuDxe, TimerDxe, etc.).  For
    the host environment, we provide NULL stubs or minimal definitions
    so the copied DXE Core code compiles and runs correctly.

    Key design decisions:
      - gCpu = NULL  → CoreSetInterruptState() becomes a natural no-op
        (the real code has "if (gCpu == NULL) return;" at the top)
      - gSmmBase2 = NULL → SMM checks are skipped
      - gTimer = NULL → CoreSetTimer uses hardcoded MIN_TIMER_TICK instead
        of gTimer->GetTimerPeriod() (handled in TimerDxeCore.c)
      - gRuntime = &gRuntimeTemplate → minimal runtime arch protocol with
        an initialized EventHead list (needed by CoreCreateEventInternal
        for EVT_RUNTIME events to insert into)

    Copyright (c) 2025, HBFAplus Contributors. All rights reserved.
    SPDX-License-Identifier: BSD-2-Clause-Patent
**/

#include "DxeMain.h"

//
// ============================================================================
// EfiEventEmptyFunction - normally from UefiLib, provided locally to
// avoid circular dependency (UefiLib depends on UefiBootServicesTableLib).
// ============================================================================
//

/**
  An empty function that serves as a no-op callback for events.
  Used by CoreInitializeEventServices for the gIdleLoopEvent.

  @param  Event    Event whose notification function is being invoked.
  @param  Context  The pointer to the notification function's context.
**/
__attribute__((weak))
VOID
EFIAPI
EfiEventEmptyFunction (
  IN EFI_EVENT  Event,
  IN VOID       *Context
  )
{
  return;
}

//
// ============================================================================
// Hardware Protocol Stubs
// ============================================================================
//

/**
  CPU Arch Protocol — NULL means CoreSetInterruptState is a no-op.
  The real DXE Core Tpl.c line 28: "if (gCpu == NULL) return;"
  Weak: DxeServicesTableLibHost may also define this.
**/
__attribute__((weak))
EFI_CPU_ARCH_PROTOCOL  *gCpu = NULL;

/**
  SMM Base2 Protocol — NULL means SMM check in CoreSetInterruptState
  is skipped entirely (never enters the gSmmBase2->InSmm path).
  Weak: DxeServicesTableLibHost may also define this.
**/
__attribute__((weak))
EFI_SMM_BASE2_PROTOCOL  *gSmmBase2 = NULL;

/**
  Timer Arch Protocol — NULL.  CoreSetTimer in TimerDxeCore.c uses a
  hardcoded DEFAULT_TIMER_TICK_DURATION instead of calling
  gTimer->GetTimerPeriod().
  Weak: if another library defines this, their version is used.
**/
__attribute__((weak))
EFI_TIMER_ARCH_PROTOCOL  *gTimer = NULL;

//
// ============================================================================
// Runtime Arch Protocol Stub
// ============================================================================
//

/**
  Minimal EFI_RUNTIME_ARCH_PROTOCOL template.
  CoreCreateEventInternal inserts EVT_RUNTIME events into
  gRuntime->EventHead.  We provide a real list head so the code
  works without crashing.  The list is never walked for actual
  runtime fixup in the host environment.
**/
EFI_RUNTIME_ARCH_PROTOCOL  gRuntimeTemplate = { 0 };
EFI_RUNTIME_ARCH_PROTOCOL  *gRuntime = &gRuntimeTemplate;

/**
  Initialize the runtime template's EventHead list.

  Must be called before CoreInitializeEventServices() so that any
  EVT_RUNTIME event creation can safely InsertTailList into EventHead.
**/
VOID
EFIAPI
HostShimInitRuntime (
  VOID
  )
{
  InitializeListHead (&gRuntimeTemplate.EventHead);
}
