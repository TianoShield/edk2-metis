/** @file ToolChainHarnessLib.h
    HBFAplus Toolchain Harness Library contract.

    Every HBFAplus harness MUST implement:
      InitializeHarness  — one-time setup (called before forkserver)
      CleanupHarness     — free persistent allocations (via atexit)
      RunTestHarness     — per-iteration fuzz execution
      GetMaxBufferSize   — maximum fuzz input size

    ToolChainHarnessLib performs generic setup before calling the harness:
      1. ProcessLibraryConstructorList (gBS/gST/mock libs)
      2. FuzzGetContext → shared MOCK_FUZZ_CONTEXT *
      3. MockEventSetAdvanceContext (set advance context for timer-driven events)
      4. Per-iteration: MockEventResetState, FuzzSetBuffer, RunTestHarness

    Copyright (c) 2019, Intel Corporation. All rights reserved.<BR>
    Copyright (c) 2025, HBFAplus Contributors. All rights reserved.
    SPDX-License-Identifier: BSD-2-Clause-Patent
**/

#ifndef _TOOLCHAIN_HARNESS_LIB_
#define _TOOLCHAIN_HARNESS_LIB_

#include "MockFuzzContext.h"

/**
  Per-iteration test execution.

  Called for each fuzz input after ToolChainHarnessLib has:
    - Reset all event/timer state (MockEventResetState)
    - Initialized the fuzz buffer pool with the current fuzz buffer
    - Obtained the shared MOCK_FUZZ_CONTEXT pointer

  The fuzz buffer is accessible via FuzzCtx->Buffer / FuzzCtx->Size.
  Use MockFuzzContextGetU8/U16/U32() to consume structured bytes.

  @param[in]  FuzzCtx  Shared fuzz context — encapsulates the fuzz buffer,
                        consumption offset, and timer advance callback.
**/
VOID
EFIAPI
RunTestHarness (
  IN MOCK_FUZZ_CONTEXT  *FuzzCtx
  );

/**
  Get maximum fuzz buffer size.

  @return  Maximum buffer size in bytes.
**/
UINTN
EFIAPI
GetMaxBufferSize (
  VOID
  );

#endif