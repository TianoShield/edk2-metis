/** @file PrintLibVAOverride.h
  VA_LIST / VA_START / VA_ARG / VA_END / VA_COPY overrides for ms_abi.

  BACKGROUND:
  ===========
  On Linux/GCC X64, EFIAPI = __attribute__((ms_abi)) and the global build
  flag -DNO_MSABI_VA_FUNCS=TRUE makes VA_LIST/VA_START/VA_ARG expand to
  SysV intrinsics (__builtin_va_*).  This is WRONG for EFIAPI variadic
  functions whose arguments arrive via the Microsoft x64 calling convention.

  The build system force-includes AutoGen.h (via -include AutoGen.h) BEFORE
  source file content.  AutoGen.h pulls in Base.h which checks NO_MSABI_VA_FUNCS
  and defines VA_LIST as a typedef and VA_START/VA_ARG/VA_END/VA_COPY as macros,
  all using SysV __builtin_va_* intrinsics.  Base.h's include guard prevents
  re-evaluation so simply #undef NO_MSABI_VA_FUNCS has no effect.

  This header is included at the TOP of each PrintLib source file (after
  AutoGen.h has been processed).  It forcibly overrides ALL VA_* symbols
  to their ms_abi equivalents so that every EFIAPI variadic function in
  PrintLib correctly captures and reads Microsoft-ABI arguments.

  AUDIT (2025):
  =============
  THE core innovation of PrintLibHost — enables EFIAPI variadic functions
  on Linux/GCC X64 host builds.  Conditionally applies only when all three
  conditions are met: __GNUC__ && MDE_CPU_X64 && NO_MSABI_VA_FUNCS.
  VA_ARG uses __builtin_va_arg (works for both ABIs) with UINTN promotion
  for types smaller than UINTN — correct per both calling conventions.
  This header MUST be included BEFORE PrintLibInternal.h in every .c file.
  Also included by the test file to fix EFIAPI variadic test helpers.
  No modifications needed — correct and thoroughly tested.

  Copyright (c) 2025, HBFAplus Contributors. All rights reserved.
  SPDX-License-Identifier: BSD-2-Clause-Patent
**/

#ifndef PRINT_LIB_VA_OVERRIDE_H_
#define PRINT_LIB_VA_OVERRIDE_H_

#if defined (__GNUC__) && defined (MDE_CPU_X64) && defined (HBFA_USE_MSABI_VA)

//
// When EFIAPI = __attribute__((ms_abi)) AND NO_MSABI_VA_FUNCS is set,
// the VA_* macros from Base.h use SysV intrinsics but EFIAPI variadic
// functions receive args via ms_abi.  Override VA_* to ms_abi intrinsics.
//
// When EFIAPI is empty (sysv_abi), this block is NOT active because
// HBFA_USE_MSABI_VA is not defined.  The standard VA_* macros (sysv_abi)
// are correct in that case.
//
#define VA_LIST  __builtin_ms_va_list

#undef VA_START
#define VA_START(Marker, Parameter)  __builtin_ms_va_start (Marker, Parameter)

#undef VA_ARG
#define VA_ARG(Marker, TYPE) \
  ((sizeof (TYPE) < sizeof (UINTN)) \
    ? (TYPE)(__builtin_va_arg (Marker, UINTN)) \
    : (TYPE)(__builtin_va_arg (Marker, TYPE)))

#undef VA_END
#define VA_END(Marker)  __builtin_ms_va_end (Marker)

#undef VA_COPY
#define VA_COPY(Dest, Start)  __builtin_ms_va_copy (Dest, Start)

#endif /* __GNUC__ && MDE_CPU_X64 && HBFA_USE_MSABI_VA */

#endif /* PRINT_LIB_VA_OVERRIDE_H_ */
