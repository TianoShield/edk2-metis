/** @file HiiLibHost.c
  Host-compatible wrapper for edk2's UefiHiiLib/HiiLib.c.

  This file includes the VA override header to fix the ms_abi / SysV
  VA_LIST mismatch, then includes the original HiiLib.c from edk2.
  The VA override ensures that HiiAddPackages (the only EFIAPI variadic
  function in HiiLib.c) correctly reads arguments passed via the
  Microsoft x64 calling convention.

  Copyright (c) 2025, HBFAplus Contributors. All rights reserved.
  SPDX-License-Identifier: BSD-2-Clause-Patent
**/

//
// Override VA_LIST / VA_START / VA_ARG / VA_END to use ms_abi intrinsics.
// Must come after AutoGen.h (force-included by -include AutoGen.h) but
// before any code that uses the VA_* macros.
//
#include "HiiLibVAOverride.h"

//
// Include the local copy of HiiLib.c (copied from edk2/MdeModulePkg/Library/UefiHiiLib/).
// The #include "InternalHiiLib.h" inside HiiLib.c resolves correctly
// because GCC searches the directory of the file containing the directive.
//
#include "HiiLib.c"
