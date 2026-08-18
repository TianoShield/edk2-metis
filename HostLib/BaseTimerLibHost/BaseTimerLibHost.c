/** @file BaseTimerLibHost.c
  Host-based implementation of TimerLib for UEFI rehosting and fuzzing.

  On a real UEFI platform the timer library accesses hardware performance
  counters and produces actual delays.  In the host-fuzzing environment:
  - Delays are no-ops (return immediately) to keep fuzzing fast.
  - Performance counter properties report a simple counting-up 64-bit
    counter with frequency 1 GHz, matching a typical UEFI platform.
  - GetTimeInNanoSecond converts ticks 1:1 (1 GHz ⇒ 1 ns/tick).

  AUDIT NOTES (HBFAplus host-fuzzing review):
  - MicroSecondDelay: No-op, returns MicroSeconds.  Correct.
  - NanoSecondDelay: FIXED - was returning 0; now returns NanoSeconds to
    match the UEFI spec and MicroSecondDelay behaviour.
  - GetPerformanceCounter: Returns 0.  Acceptable for fuzzing.
  - GetPerformanceCounterProperties: FIXED - now writes StartValue=0 and
    EndValue=MAX_UINT64 to output pointers when non-NULL, matching a
    counting-up 64-bit counter.  Returns 1 GHz frequency.
  - GetTimeInNanoSecond: FIXED - returns Ticks (1 ns per tick at 1 GHz).

  Copyright (c) 2018, Intel Corporation. All rights reserved.<BR>
  SPDX-License-Identifier: BSD-2-Clause-Patent
**/

#include <Base.h>
#include <Library/TimerLib.h>
#include <Library/DebugLib.h>

/**
  Stalls the CPU for at least the given number of microseconds.

  AUDIT: No-op delay is correct for host fuzzing — we do not want real delays
  slowing down the fuzzer.  Returns MicroSeconds per UEFI spec.

  @param  MicroSeconds  The minimum number of microseconds to delay.
  @return The value of MicroSeconds inputted.
**/
UINTN
EFIAPI
MicroSecondDelay (
  IN      UINTN                     MicroSeconds
  )
{
  return MicroSeconds;
}

/**
  Stalls the CPU for at least the given number of nanoseconds.

  AUDIT: FIXED — was returning 0.  Now returns NanoSeconds per UEFI spec
  (consistent with MicroSecondDelay).

  @param  NanoSeconds The minimum number of nanoseconds to delay.
  @return The value of NanoSeconds inputted.
**/
UINTN
EFIAPI
NanoSecondDelay (
  IN      UINTN                     NanoSeconds
  )
{
  return NanoSeconds;
}

/**
  Retrieves the current value of a 64-bit free running performance counter.

  Returns a monotonically-increasing counter that advances by 1 000 000 ticks
  (= 1 ms at the reported 1 GHz frequency) on every call.  This ensures that
  timeout-based polling loops in real UEFI drivers (e.g. XhciDxe
  XhcWaitOpRegBit) expire within a small number of iterations instead of
  spinning for millions of rounds — eliminating false-positive hangs during
  fuzzing while remaining deterministic.

  @return The current value of the free running performance counter.
**/
UINT64
EFIAPI
GetPerformanceCounter (
  VOID
  )
{
  static UINT64  mCounter = 0;

  mCounter += 1000000;  // +1 ms per call at 1 GHz
  return mCounter;
}

/**
  Retrieves the 64-bit frequency in Hz and the range of performance counter
  values.

  AUDIT: FIXED — previously did not write StartValue/EndValue, so callers
  could read uninitialised stack memory.  Now writes StartValue=0 and
  EndValue=MAX_UINT64 (counting-up 64-bit counter).  Frequency is 1 GHz.

  @param  StartValue  The value the performance counter starts with when it
                      rolls over.  May be NULL.
  @param  EndValue    The value that the performance counter ends with before
                      it rolls over.  May be NULL.

  @return The frequency in Hz (1,000,000,000 = 1 GHz).
**/
UINT64
EFIAPI
GetPerformanceCounterProperties (
  OUT      UINT64                    *StartValue,  OPTIONAL
  OUT      UINT64                    *EndValue     OPTIONAL
  )
{
  if (StartValue != NULL) {
    *StartValue = 0;
  }
  if (EndValue != NULL) {
    *EndValue = (UINT64)(-1);
  }
  //
  // Report 1 GHz frequency — a common UEFI platform value.
  // This keeps GetTimeInNanoSecond() conversion simple: 1 tick = 1 ns.
  //
  return 1000000000ULL;
}

/**
  Converts elapsed ticks of performance counter to time in nanoseconds.

  AUDIT: FIXED — was returning 0 regardless of Ticks.  At 1 GHz frequency
  each tick is 1 ns, so we return Ticks directly.

  @param  Ticks     The number of elapsed ticks of running performance counter.
  @return The elapsed time in nanoseconds.
**/
UINT64
EFIAPI
GetTimeInNanoSecond (
  IN      UINT64                     Ticks
  )
{
  //
  // At 1 GHz, 1 tick = 1 nanosecond.
  //
  return Ticks;
}
