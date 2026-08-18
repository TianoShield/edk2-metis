/** @file HiiLibVAOverride.h
  VA_LIST / VA_START / VA_ARG / VA_END / VA_COPY overrides for ms_abi.

  On Linux/GCC X64, EFIAPI = __attribute__((ms_abi)) and the global build
  flag -DNO_MSABI_VA_FUNCS=TRUE makes VA_LIST/VA_START/VA_ARG expand to
  SysV intrinsics (__builtin_va_*).  This is WRONG for EFIAPI variadic
  functions (like HiiAddPackages) whose arguments arrive via the Microsoft
  x64 calling convention.

  This header forcibly overrides all VA_* symbols to their ms_abi
  equivalents so that HiiAddPackages (the only variadic function in
  HiiLib.c) correctly captures and reads Microsoft-ABI arguments.

  Copyright (c) 2025, HBFAplus Contributors. All rights reserved.
  SPDX-License-Identifier: BSD-2-Clause-Patent
**/

#ifndef HII_LIB_VA_OVERRIDE_H_
#define HII_LIB_VA_OVERRIDE_H_

#if defined (__GNUC__) && defined (MDE_CPU_X64) && defined (HBFA_USE_MSABI_VA)

//
// When EFIAPI is sysv_abi (host-based builds without ms_abi),
// the VA_* macros from Base.h already use __builtin_va_* (sysv_abi)
// which is correct.  No ms_abi override needed.
//
// NOTE: The ms_abi overrides below have been DISABLED because
// HBFAplus no longer uses -DEFIAPI=__attribute__((ms_abi)).
// All EFIAPI functions use sysv_abi on host builds.
//

#endif /* __GNUC__ && MDE_CPU_X64 && HBFA_USE_MSABI_VA */

#endif /* HII_LIB_VA_OVERRIDE_H_ */
