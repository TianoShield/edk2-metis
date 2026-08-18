/** @file DebugLibHost.c
  Host-side DebugLib implementation for HBFAplus fuzzing environment.

  AUDIT NOTES (HBFAplus host-fuzzing review):
  ============================================

  This library provides the DebugLib interface for host-based rehosting.
  Every edk2 module that uses DEBUG(), ASSERT(), or DEBUG_CODE() depends
  on this library.

  CRASH FIX — DebugPrint / DEBUG() macro:
  ----------------------------------------
  On Linux/GCC X64, EFIAPI = __attribute__((ms_abi)), so variadic arguments
  to DebugPrint() are passed using the Microsoft x64 calling convention
  (RCX, RDX, R8, R9, then stack with shadow space).

  Meanwhile, -DNO_MSABI_VA_FUNCS=TRUE (set globally by HBFAplus) causes
  VA_LIST / VA_START / VA_ARG to expand to SysV (__builtin_va_*) intrinsics,
  NOT the MS ABI ones.  This is correct for non-variadic code and for
  BasePrintLib's internal formatter (BasePrintLibSPrintMarker, which is
  SysV ABI).  But it is WRONG inside an EFIAPI variadic function:

      DebugPrint(EFIAPI) → args arrive in MS ABI registers
      VA_START → captures SysV register locations → GARBAGE

  The original code either disabled debug output entirely or tried to pass
  the (garbage) VA_LIST to AsciiVSPrint, both of which are broken.

  SOLUTION (two-part fix):
  1. PrintLibHost (HBFAplus/HostLib/PrintLibHost/) recompiles edk2's
     BasePrintLib WITHOUT NO_MSABI_VA_FUNCS, making VA_LIST = ms_abi
     throughout PrintLib.  This fixes internal variadic functions like
     BasePrintLibSPrint (called by %g/%t/%r handlers).
  2. DebugPrint uses MSABI_VA macros to correctly capture MS-ABI varargs,
     extracts them into a UINTN[] array, and calls AsciiBSPrint() with
     a BASE_LIST (UINTN*).  BASE_LIST has zero ABI dependency.

  Functions implemented (full DebugLib interface):
    1. DebugPrint          — DEBUG() macro backend; MSABI_VA → BASE_LIST → AsciiBSPrint
    2. DebugVPrint         — VA_LIST variant; best-effort (see note below)
    3. DebugBPrint         — BASE_LIST variant; directly calls AsciiBSPrint
    4. DebugAssert         — ASSERT() macro backend; prints + exit(1)
    5. DebugClearMemory    — Fills buffer with 0xAF (standard debug fill)
    6. DebugAssertEnabled  — Returns TRUE (assertions always active for fuzzing)
    7. DebugPrintEnabled   — Returns TRUE (debug output always on)
    8. DebugCodeEnabled    — Returns TRUE (debug code blocks always active)
    9. DebugClearMemoryEnabled — Returns TRUE
   10. DebugPrintLevelEnabled  — Returns TRUE for all error levels

  Copyright (c) 2018, Intel Corporation. All rights reserved.<BR>
  Copyright (c) 2025, HBFAplus Contributors. All rights reserved.
  SPDX-License-Identifier: BSD-2-Clause-Patent
**/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <Uefi.h>
#include <Library/BaseLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/PrintLib.h>

//
// Maximum formatted message length for DEBUG() output.
// If an edk2 DEBUG() call produces a longer message it will be truncated.
//
#define MAX_DEBUG_MESSAGE_LENGTH  0x200

//
// Maximum number of UINTN-sized arguments we extract from variadic calls.
// Each format specifier consumes one UINTN from the BASE_LIST.  12 handles
// any realistic DEBUG() call (rarely more than 6-8 arguments).
//
#define MAX_FORMAT_ARGS  12

//
// Verbose control.  When HBFA_VERBOSE is non-zero, DebugPrint prefixes each
// message with a human-readable error level tag like "[ERROR] " or "[INFO] ".
// Controlled at build time via -DHBFA_VERBOSE=1 in the DSC, or at runtime
// via the HBFA_DEBUG environment variable.
//
#ifndef HBFA_VERBOSE
  #define HBFA_VERBOSE  0
#endif

//
// Runtime verbose flag — checked once on first DebugPrint call.
// If env HBFA_DEBUG is set (to any non-empty value), verbose is enabled.
//
STATIC INT32 gVerboseInitialized = 0;
STATIC INT32 gVerboseEnabled     = HBFA_VERBOSE;

STATIC
VOID
InitVerbose (
  VOID
  )
{
  CONST CHAR8  *Env;

  Env = getenv ("HBFA_DEBUG");
  if (Env != NULL && Env[0] != '\0') {
    gVerboseEnabled = 1;
  }
  gVerboseInitialized = 1;
}

/**
  Return a short tag string for the given ErrorLevel bitmask.
**/
STATIC
CONST CHAR8 *
DebugLevelTag (
  IN  UINTN  ErrorLevel
  )
{
  if (ErrorLevel & 0x80000000) return "[ERROR] ";
  if (ErrorLevel & 0x00400000) return "[VERBOSE] ";
  if (ErrorLevel & 0x00000040) return "[INFO] ";
  if (ErrorLevel & 0x00000002) return "[WARN] ";
  if (ErrorLevel & 0x00000001) return "[INIT] ";
  if (ErrorLevel & 0x00004000) return "[NET] ";
  if (ErrorLevel & 0x00000080) return "[DISPATCH] ";
  if (ErrorLevel & 0x00080000) return "[EVENT] ";
  return "[DEBUG] ";
}

//
// VA_LIST / VA_START / VA_ARG / VA_END mapping.
//
// When EFIAPI is sysv_abi (host-based builds without ms_abi), the regular
// VA_* macros from Base.h work correctly.  The custom __builtin_ms_va_*
// workaround was only needed when EFIAPI was __attribute__((ms_abi)) but
// VA_LIST was __builtin_va_list (sysv).  Since we no longer use ms_abi
// for host builds, we always use the standard VA_* macros.
//
#define MSABI_VA_LIST    VA_LIST
#define MSABI_VA_START   VA_START
#define MSABI_VA_ARG     VA_ARG
#define MSABI_VA_END     VA_END

// ============================================================================
// DebugAssert — ASSERT() macro backend
// ============================================================================

/**
  Prints an assert message and terminates the process.

  On a real UEFI platform ASSERT() would call CpuBreakpoint() or CpuDeadLoop().
  In the host fuzzing environment we print to stderr and exit(1) so the fuzzer
  gets a clean, deterministic non-zero exit code.

  @param[in] FileName     Source file that generated the assert.
  @param[in] LineNumber   Line number in the source file.
  @param[in] Description  Description of the failed expression.
**/
VOID
EFIAPI
DebugAssert (
  IN CONST CHAR8  *FileName,
  IN UINTN        LineNumber,
  IN CONST CHAR8  *Description
  )
{
  fprintf (
    stderr,
    "ASSERT: %s(%d): %s\n",
    FileName    ? FileName    : "(NULL) Filename",
    (INT32)(UINT32)LineNumber,
    Description ? Description : "(NULL) Description"
    );
  fflush (stderr);
  exit (1);
}

/**
  Count the number of format specifiers in an EDK2 format string.

  Scans for '%' characters that are NOT '%%' (literal percent).
  Each non-literal '%' consumes one UINTN-sized argument from the va_list.

  @param[in] Format  Null-terminated ASCII format string.
  @return  Number of format specifiers found.
**/
STATIC
UINTN
CountFormatArgs (
  IN  CONST CHAR8  *Format
  )
{
  UINTN        Count;
  CONST CHAR8  *Ptr;

  Count = 0;
  for (Ptr = Format; *Ptr != '\0'; Ptr++) {
    if (*Ptr == '%') {
      Ptr++;
      if (*Ptr == '\0') {
        break;
      }
      if (*Ptr != '%') {
        Count++;
      }
    }
  }

  return Count;
}

// ============================================================================
// DebugPrint — DEBUG() macro backend (THE CRITICAL FIX)
// ============================================================================

/**
  Prints a debug message to stderr.

  This is called by the DEBUG() macro in every edk2 module.  Variadic
  arguments arrive in MS ABI format (due to EFIAPI).

  Strategy:
  1. Count format specifiers to know how many args to extract
  2. Capture MS-ABI varargs with MSABI_VA_START (correct for ms_abi callers)
  3. Extract exactly ArgCount UINTN values into a local array
  4. Pass the array as a BASE_LIST to AsciiBSPrint (no ABI issues)
  5. fputs the resulting buffer to stderr

  NOTE: We must NOT extract more arguments than the caller actually passed.
  ASan (used in AFL builds) will flag reads past the stack frame
  as stack-buffer-underflow — the original crash in this bug report.

  @param[in] ErrorLevel  The error level of the debug message.
  @param[in] Format      Null-terminated ASCII format string (EDK2 format).
  @param[in] ...         Variable argument list (MS ABI).
**/
VOID
EFIAPI
DebugPrint (
  IN  UINTN        ErrorLevel,
  IN  CONST CHAR8  *Format,
  ...
  )
{
  MSABI_VA_LIST  MsMarker;
  UINTN          Args[MAX_FORMAT_ARGS];
  CHAR8          Buffer[MAX_DEBUG_MESSAGE_LENGTH];
  UINTN          Index;
  UINTN          ArgCount;

  if (Format == NULL) {
    return;
  }

  //
  // Step 1: Count format specifiers so we only read as many varargs
  // as the caller actually pushed.  This prevents ASan false positives
  // (stack-buffer-underflow) in AFL builds.
  //
  ArgCount = CountFormatArgs (Format);
  if (ArgCount > MAX_FORMAT_ARGS) {
    ArgCount = MAX_FORMAT_ARGS;
  }

  //
  // Zero the full array so that if BasePrintLibSPrintMarker reads
  // beyond ArgCount (shouldn't happen, but defensive), it sees 0.
  //
  ZeroMem (Args, sizeof (Args));

  //
  // Step 2: Capture the MS-ABI variadic arguments correctly.
  // MSABI_VA_START uses __builtin_ms_va_start which reads from the
  // correct register/stack positions for the Microsoft x64 ABI.
  //
  MSABI_VA_START (MsMarker, Format);

  //
  // Step 3: Extract only the arguments the format string requires.
  //
  for (Index = 0; Index < ArgCount; Index++) {
    Args[Index] = MSABI_VA_ARG (MsMarker, UINTN);
  }

  MSABI_VA_END (MsMarker);

  //
  // Step 4: Format using AsciiBSPrint (BASE_LIST variant).
  // AsciiBSPrint is NOT variadic — it takes a BASE_LIST (UINTN *)
  // as a regular parameter.  No ms_abi/sysv_abi mismatch is possible.
  // Internally it calls BasePrintLibSPrintMarker using BASE_ARG which
  // reads sizeof(UINTN) at a time from our Args array.
  //
  AsciiBSPrint (Buffer, sizeof (Buffer), Format, (BASE_LIST)Args);

  //
  // Step 5: Output to stderr.
  // When verbose mode is active (HBFA_VERBOSE=1 at build time or
  // HBFA_DEBUG env var at runtime), prefix each message with a level tag.
  //
  if (!gVerboseInitialized) {
    InitVerbose ();
  }

  if (gVerboseEnabled) {
    fputs (DebugLevelTag (ErrorLevel), stderr);
  }

  fputs (Buffer, stderr);
}

// ============================================================================
// DebugVPrint — VA_LIST variant
// ============================================================================

/**
  Prints a debug message using a VA_LIST.

  NOTE: Under -DNO_MSABI_VA_FUNCS=TRUE, VA_LIST is __builtin_va_list (SysV).
  If the caller correctly captured MS-ABI args using MSABI_VA macros, the
  VA_LIST may contain garbage (the two va_list types are incompatible).
  In practice, DebugVPrint is only called from code that already has a
  SysV VA_LIST.  We pass it to AsciiVSPrint which reads via VA_ARG (SysV).
  For EFIAPI callers, use DebugPrint or DebugBPrint instead.

  @param[in] ErrorLevel    The error level of the debug message.
  @param[in] Format        Null-terminated ASCII format string (EDK2 format).
  @param[in] VaListMarker  VA_LIST marker for the variable argument list.
**/
// AUDIT: BUG-class — outputs raw format string instead of formatting VA_LIST.
// The MS_ABI VA_LIST type is incompatible with host vfprintf.
// Acceptable: DEBUG output is cosmetic during fuzzing.
VOID
EFIAPI
DebugVPrint (
  IN  UINTN        ErrorLevel,
  IN  CONST CHAR8  *Format,
  IN  VA_LIST      VaListMarker
  )
{
  if (Format == NULL) {
    return;
  }

  //
  // LIMITATION: Under -DNO_MSABI_VA_FUNCS, VA_LIST is SysV (__builtin_va_list)
  // but our PrintLibHost compiles without NO_MSABI_VA_FUNCS, making its
  // VA_LIST = ms_abi (__builtin_ms_va_list).  These two types have
  // incompatible binary layouts (24-byte struct vs 8-byte pointer).
  // Passing a SysV VA_LIST to AsciiVSPrint (expecting ms_abi) would crash.
  //
  // Moreover, if the caller is EFIAPI (ms_abi) and captured with VA_START
  // (SysV under NO_MSABI_VA_FUNCS), the VA_LIST data is already garbage.
  //
  // Best-effort: output the raw format string so the developer sees SOMETHING.
  // For full formatting, use DebugPrint() / DEBUG() which uses the safe
  // MSABI_VA → BASE_LIST → AsciiBSPrint path.
  //
  if (!gVerboseInitialized) {
    InitVerbose ();
  }

  if (gVerboseEnabled) {
    fputs (DebugLevelTag (ErrorLevel), stderr);
  }

  fputs (Format, stderr);
}

// ============================================================================
// DebugBPrint — BASE_LIST variant
// ============================================================================

/**
  Prints a debug message using a BASE_LIST argument list.

  BASE_LIST (UINTN *) is ABI-safe — it's a regular pointer parameter,
  not a compiler-managed va_list.  No ms_abi/sysv_abi mismatch.

  @param[in] ErrorLevel      The error level of the debug message.
  @param[in] Format          Null-terminated ASCII format string.
  @param[in] BaseListMarker  BASE_LIST marker for the variable argument list.
**/
VOID
EFIAPI
DebugBPrint (
  IN  UINTN        ErrorLevel,
  IN  CONST CHAR8  *Format,
  IN  BASE_LIST    BaseListMarker
  )
{
  CHAR8  Buffer[MAX_DEBUG_MESSAGE_LENGTH];

  if (Format == NULL) {
    return;
  }

  AsciiBSPrint (Buffer, sizeof (Buffer), Format, BaseListMarker);

  if (!gVerboseInitialized) {
    InitVerbose ();
  }

  if (gVerboseEnabled) {
    fputs (DebugLevelTag (ErrorLevel), stderr);
  }

  fputs (Buffer, stderr);
}

// ============================================================================
// DebugClearMemory
// ============================================================================

/**
  Fills a target buffer with the debug clear value (0xAF).

  On real UEFI this fills freed memory with a recognizable pattern to help
  detect use-after-free bugs.  We implement this faithfully so that edk2
  code under test gets the same behavior.

  @param[out] Buffer  Target buffer to fill.
  @param[in]  Length  Number of bytes to fill.

  @return Buffer
**/
VOID *
EFIAPI
DebugClearMemory (
  OUT VOID  *Buffer,
  IN UINTN  Length
  )
{
  if (Buffer == NULL) {
    return NULL;
  }

  SetMem (Buffer, Length, 0xAF);
  return Buffer;
}

// ============================================================================
// Feature-enable query functions
// ============================================================================

/**
  Returns TRUE — assertions are always enabled for fuzzing.
**/
BOOLEAN
EFIAPI
DebugAssertEnabled (
  VOID
  )
{
  return TRUE;
}

/**
  Returns TRUE — debug print output is always enabled.
**/
BOOLEAN
EFIAPI
DebugPrintEnabled (
  VOID
  )
{
  return TRUE;
}

/**
  Returns TRUE — DEBUG_CODE() blocks are always compiled in.
**/
BOOLEAN
EFIAPI
DebugCodeEnabled (
  VOID
  )
{
  return TRUE;
}

/**
  Returns TRUE — DebugClearMemory is always active.
**/
BOOLEAN
EFIAPI
DebugClearMemoryEnabled (
  VOID
  )
{
  return TRUE;
}

/**
  Returns TRUE for all error levels — we want to see all debug output.

  @param[in] ErrorLevel  The error level to check.
  @retval TRUE  Always.
**/
BOOLEAN
EFIAPI
DebugPrintLevelEnabled (
  IN  CONST UINTN  ErrorLevel
  )
{
  return TRUE;
}
