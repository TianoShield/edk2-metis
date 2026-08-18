## @file HBFAplusBuildOption.dsc
#
#  HBFAplus Build Options for Host-Based Fuzzing
#
#  This file defines compiler and linker flags for building UEFI code to run
#  on a Linux host for fuzzing with AFL++ and coverage analysis.
#
#  Key Features:
#  - Removes -nostdlib to allow linking with host libc (required for ASan)
#  - Configures output as native executable (not EFI binary)
#  - Enables Address Sanitizer (ASan) for memory error detection
#  - Supports multiple toolchains: GCC5, AFL
#
#  Copyright (c) 2024, HBFAplus Contributors. All rights reserved.
#  SPDX-License-Identifier: BSD-2-Clause-Patent
#
##

#=============================================================================
# Common Build Options
#=============================================================================

[BuildOptions]
  #---------------------------------------------------------------------------
  # Microsoft Visual Studio (Windows) - Not primary target but supported
  #---------------------------------------------------------------------------
  MSFT:*_*_*_CC_FLAGS = /D _CRT_SECURE_NO_WARNINGS

  #---------------------------------------------------------------------------
  # GCC Common Flags (IA32)
  #---------------------------------------------------------------------------
  # Note: Using == to override default EDK2 flags completely
  # -m32: 32-bit mode
  # -g: Debug symbols
  # -fshort-wchar: UEFI uses 16-bit wchar_t
  # -fno-strict-aliasing: Required for UEFI type punning
  # -Wall: Enable all warnings
  # -malign-double: Align doubles on 8-byte boundary
  # -idirafter/usr/include: Add system includes last
  #
  GCC:*_*_IA32_CC_FLAGS == -m32 -g -fshort-wchar -fno-strict-aliasing -Wall -malign-double -idirafter/usr/include -c -include $(DEST_DIR_DEBUG)/AutoGen.h
  GCC:*_*_IA32_PP_FLAGS == -m32 -E -x assembler-with-cpp -include $(DEST_DIR_DEBUG)/AutoGen.h
  GCC:*_*_IA32_ASM_FLAGS == -m32 -c -x assembler -imacros $(DEST_DIR_DEBUG)/AutoGen.h

  #---------------------------------------------------------------------------
  # GCC Common Flags (X64)
  #---------------------------------------------------------------------------
  GCC:*_*_X64_CC_FLAGS == -m64 -g -fshort-wchar -fno-strict-aliasing -Wall -malign-double -idirafter/usr/include -c -include $(DEST_DIR_DEBUG)/AutoGen.h
  #
  # NOTE: Do NOT add -DEFIAPI=__attribute__((ms_abi)) here.
  # Host-based fuzzing builds native Linux ELF executables using System V ABI.
  # Using ms_abi with GCC's __builtin_va_arg causes crashes in variadic
  # EFIAPI functions (e.g. HiiAddPackages) because GCC generates sysv_abi
  # va_arg code even for ms_abi functions.  ProcessorBind.h defines EFIAPI
  # as empty for GCC, giving consistent sysv_abi throughout.
  #
  GCC:*_GCC5_X64_CC_FLAGS = -DUSING_LTO -O0 -fno-omit-frame-pointer
  GCC:*_*_X64_PP_FLAGS == -m64 -E -x assembler-with-cpp -include $(DEST_DIR_DEBUG)/AutoGen.h
  GCC:*_*_X64_ASM_FLAGS == -m64 -c -x assembler -imacros $(DEST_DIR_DEBUG)/AutoGen.h

  #---------------------------------------------------------------------------
  # GCC5 Toolchain - Code Coverage
  #---------------------------------------------------------------------------
  # --coverage: Enable gcov instrumentation for code coverage
  # Used with GenCodeCoverage.py to generate HTML coverage reports
  # -O0: No optimization — preserves all local variables for GDB debugging
  # -fno-omit-frame-pointer: Keep frame pointers for accurate backtraces
  #
  GCC:*_GCC5_*_CC_FLAGS = --coverage
  GCC:*_GCC5_*_DLINK_FLAGS = --coverage
  GCC:*_GCC5_X64_CC_FLAGS = "-DNO_MSABI_VA_FUNCS=TRUE"

  #
  # Verbose debug output — prefix each DEBUG() message with its level tag
  # like [ERROR], [INFO], [WARN], etc.  Set to 1 to enable at build time.
  # Can also be enabled at runtime: HBFA_DEBUG=1 ./TestDhcp6Driver input.bin
  #
  GCC:*_GCC5_*_CC_FLAGS = "-DHBFA_VERBOSE=1"

  #---------------------------------------------------------------------------
  # AFL/AFL++ Toolchain
  #---------------------------------------------------------------------------
  # afl-gcc-fast: AFL++ compiler wrapper with instrumentation
  # -DUSING_LTO: Link-time optimization for better instrumentation
  # -DNO_MSABI_VA_FUNCS=TRUE: Use System V ABI for varargs (required for host execution)
  # The fuzzing instrumentation is added by afl-gcc-fast automatically
  #
  GCC:*_AFL_*_CC_PATH = afl-gcc-fast
  GCC:*_AFL_X64_CC_FLAGS = -DUSING_LTO "-DNO_MSABI_VA_FUNCS=TRUE"

  #---------------------------------------------------------------------------
  # AFLCLANG Toolchain (AFL++ clang variant)
  #---------------------------------------------------------------------------
  # Both flags are required and both are dropped by the `==` replace above.
  # NO_MSABI_VA_FUNCS: clang rejects __builtin_ms_va_start in SysV functions.
  # -fno-builtin: clang rewrites StrLen()'s CHAR16 scan into wcslen(), which
  # assumes a 4-byte wchar_t.
  GCC:*_AFLCLANG_X64_CC_FLAGS = -DUSING_LTO "-DNO_MSABI_VA_FUNCS=TRUE" -fno-builtin

  # Must be in this general section, not USER_DEFINED below:
  # ToolChainHarnessLib.inf is MODULE_TYPE = BASE, so USER_DEFINED flags never
  # reach it and the link fails on an undefined LLVMFuzzerTestOneInput.
  GCC:*_AFLCLANG_X64_CC_FLAGS = -DTEST_WITH_LIBFUZZER

#=============================================================================
# USER_DEFINED Module Type Build Options
#=============================================================================
#
# These options apply to fuzz harness modules (MODULE_TYPE = USER_DEFINED)
# CRITICAL: This section overrides the default EDK2 linker flags to:
#   1. NOT use -nostdlib (allows linking with libc for host execution)
#   2. Output as native executable (not EFI binary)
#   3. Enable proper library linking order
#
[BuildOptions.common.EDKII.USER_DEFINED]
  #---------------------------------------------------------------------------
  # MSFT Linker Options (Windows)
  #---------------------------------------------------------------------------
  MSFT:*_*_IA32_DLINK_FLAGS == /out:"$(BIN_DIR)\$(BASE_NAME).exe" /base:0x10000000 /pdb:"$(BIN_DIR)\$(BASE_NAME).pdb" /LIBPATH:"$(VCINSTALLDIR)\Lib" /LIBPATH:"$(VCINSTALLDIR)\PlatformSdk\Lib" /LIBPATH:"%UniversalCRTSdkDir%lib\%UCRTVersion%\ucrt\x86" /LIBPATH:"%WindowsSdkDir%lib\%WindowsSDKLibVersion%\um\x86" /NOLOGO /SUBSYSTEM:CONSOLE /IGNORE:4086 /MAP /OPT:REF /DEBUG /MACHINE:I386 /LTCG Kernel32.lib MSVCRTD.lib Gdi32.lib User32.lib Winmm.lib Advapi32.lib
  MSFT:*_VS2015_IA32_DLINK_FLAGS == /out:"$(BIN_DIR)\$(BASE_NAME).exe" /base:0x10000000 /pdb:"$(BIN_DIR)\$(BASE_NAME).pdb" /LIBPATH:"$(VCINSTALLDIR)\Lib" /LIBPATH:"$(VCINSTALLDIR)\PlatformSdk\Lib" /LIBPATH:"%UniversalCRTSdkDir%lib\%UCRTVersion%\ucrt\x86" /LIBPATH:"%WindowsSdkDir%lib\%WindowsSDKLibVersion%\um\x86" /NOLOGO /SUBSYSTEM:CONSOLE /IGNORE:4086 /MAP /OPT:REF /DEBUG /MACHINE:I386 /LTCG Kernel32.lib MSVCRTD.lib vcruntimed.lib ucrtd.lib Gdi32.lib User32.lib Winmm.lib Advapi32.lib
  MSFT:*_VS2017_IA32_DLINK_FLAGS == /out:"$(BIN_DIR)\$(BASE_NAME).exe" /base:0x10000000 /pdb:"$(BIN_DIR)\$(BASE_NAME).pdb" /LIBPATH:"%VCToolsInstallDir%lib\x86" /LIBPATH:"%UniversalCRTSdkDir%lib\%UCRTVersion%\ucrt\x86" /LIBPATH:"%WindowsSdkDir%lib\%WindowsSDKLibVersion%\um\x86" /NOLOGO /SUBSYSTEM:CONSOLE /IGNORE:4086 /MAP /OPT:REF /DEBUG /MACHINE:I386 /LTCG Kernel32.lib MSVCRTD.lib vcruntimed.lib ucrtd.lib Gdi32.lib User32.lib Winmm.lib Advapi32.lib
  MSFT:*_*_IA32_CC_FLAGS == /nologo /W4 /WX /Gy /c /D UNICODE /Od /FIAutoGen.h /EHs-c- /GF /Gs8192 /Zi /Gm /D _CRT_SECURE_NO_WARNINGS /D _CRT_SECURE_NO_DEPRECATE
  MSFT:*_*_IA32_PP_FLAGS == /nologo /E /TC /FIAutoGen.h
  MSFT:*_*_IA32_ASM_FLAGS == /nologo /W3 /WX /c /coff /Cx /Zd /W0 /Zi
  MSFT:*_*_IA32_ASMLINK_FLAGS == /link /nologo /tiny

  MSFT:*_*_X64_DLINK_FLAGS == /out:"$(BIN_DIR)\$(BASE_NAME).exe" /base:0x10000000 /pdb:"$(BIN_DIR)\$(BASE_NAME).pdb" /LIBPATH:"$(VCINSTALLDIR)\Lib\AMD64" /LIBPATH:"%UniversalCRTSdkDir%lib\%UCRTVersion%\ucrt\x64" /LIBPATH:"%WindowsSdkDir%lib\%WindowsSDKLibVersion%\um\x64" /NOLOGO /SUBSYSTEM:CONSOLE /IGNORE:4086 /MAP /OPT:REF /DEBUG /MACHINE:AMD64 /LTCG Kernel32.lib MSVCRTD.lib Gdi32.lib User32.lib Winmm.lib Advapi32.lib
  MSFT:*_VS2015_X64_DLINK_FLAGS == /out:"$(BIN_DIR)\$(BASE_NAME).exe" /base:0x10000000 /pdb:"$(BIN_DIR)\$(BASE_NAME).pdb" /LIBPATH:"$(VCINSTALLDIR)\Lib\AMD64" /LIBPATH:"%UniversalCRTSdkDir%lib\%UCRTVersion%\ucrt\x64" /LIBPATH:"%WindowsSdkDir%lib\%WindowsSDKLibVersion%\um\x64" /NOLOGO /SUBSYSTEM:CONSOLE /IGNORE:4086 /MAP /OPT:REF /DEBUG /MACHINE:AMD64 /LTCG Kernel32.lib MSVCRTD.lib vcruntimed.lib ucrtd.lib Gdi32.lib User32.lib Winmm.lib Advapi32.lib
  MSFT:*_VS2017_X64_DLINK_FLAGS == /out:"$(BIN_DIR)\$(BASE_NAME).exe" /base:0x10000000 /pdb:"$(BIN_DIR)\$(BASE_NAME).pdb" /LIBPATH:"%VCToolsInstallDir%lib\x64" /LIBPATH:"%UniversalCRTSdkDir%lib\%UCRTVersion%\ucrt\x64" /LIBPATH:"%WindowsSdkDir%lib\%WindowsSDKLibVersion%\um\x64" /NOLOGO /SUBSYSTEM:CONSOLE /IGNORE:4086 /MAP /OPT:REF /DEBUG /MACHINE:AMD64 /LTCG Kernel32.lib MSVCRTD.lib vcruntimed.lib ucrtd.lib Gdi32.lib User32.lib Winmm.lib Advapi32.lib
  MSFT:*_*_X64_CC_FLAGS == /nologo /W4 /WX /Gy /c /D UNICODE /Od /FIAutoGen.h /EHs-c- /GF /Gs8192 /Zi /Gm /D _CRT_SECURE_NO_WARNINGS /D _CRT_SECURE_NO_DEPRECATE
  MSFT:*_*_X64_PP_FLAGS == /nologo /E /TC /FIAutoGen.h
  MSFT:*_*_X64_ASM_FLAGS == /nologo /W3 /WX /c /Cx /Zd /W0 /Zi
  MSFT:*_*_X64_ASMLINK_FLAGS == /link /nologo

  #---------------------------------------------------------------------------
  # GCC Linker Options (Linux) - CRITICAL FOR HOST EXECUTION
  #---------------------------------------------------------------------------
  # -o $(BIN_DIR)/$(BASE_NAME): Output as native executable
  # -m32/-m64: 32/64-bit mode
  # -L/usr/X11R6/lib: X11 library path (for some dependencies)
  # NOTE: No -nostdlib! This allows linking with libc (required for ASan)
  #
  GCC:*_*_IA32_DLINK_FLAGS == -o $(BIN_DIR)/$(BASE_NAME) -m32 -L/usr/X11R6/lib
  GCC:*_*_IA32_CC_FLAGS == -m32 -g -fshort-wchar -fno-strict-aliasing -Wall -malign-double -idirafter/usr/include -c -include $(DEST_DIR_DEBUG)/AutoGen.h
  GCC:*_*_IA32_PP_FLAGS == -m32 -E -x assembler-with-cpp -include $(DEST_DIR_DEBUG)/AutoGen.h
  GCC:*_*_IA32_ASM_FLAGS == -m32 -c -x assembler -imacros $(DEST_DIR_DEBUG)/AutoGen.h
  GCC:*_*_IA32_DLINK2_FLAGS == -Wno-error -no-pie

  GCC:*_*_X64_DLINK_FLAGS == -o $(BIN_DIR)/$(BASE_NAME) -m64 -L/usr/X11R6/lib
  GCC:*_GCC5_X64_DLINK_FLAGS == -o $(BIN_DIR)/$(BASE_NAME) -m64 -L/usr/X11R6/lib
  GCC:*_*_X64_CC_FLAGS == -m64 -g -fshort-wchar -fno-strict-aliasing -Wall -malign-double -idirafter/usr/include -c -include $(DEST_DIR_DEBUG)/AutoGen.h
  GCC:*_GCC5_X64_CC_FLAGS = -DUSING_LTO -O0 -fno-omit-frame-pointer
  GCC:*_*_X64_PP_FLAGS == -m64 -E -x assembler-with-cpp -include $(DEST_DIR_DEBUG)/AutoGen.h
  GCC:*_*_X64_ASM_FLAGS == -m64 -c -x assembler -imacros $(DEST_DIR_DEBUG)/AutoGen.h
  GCC:*_*_X64_DLINK2_FLAGS == -Wno-error -no-pie

  # GCC5 with stack protection and coverage
  # -O0: No optimization — preserves all local variables for GDB debugging
  # -fno-omit-frame-pointer: Keep frame pointers for accurate backtraces
  GCC:*_GCC5_*_CC_FLAGS = -fstack-protector -fstack-protector-strong -fstack-protector-all
  GCC:*_GCC5_*_CC_FLAGS = --coverage
  GCC:*_GCC5_*_DLINK_FLAGS = --coverage
  GCC:*_GCC5_X64_CC_FLAGS = "-DNO_MSABI_VA_FUNCS=TRUE"

  # AFL for USER_DEFINED modules
  GCC:*_AFL_*_CC_PATH = afl-gcc-fast
  GCC:*_AFL_X64_CC_FLAGS = -DUSING_LTO "-DNO_MSABI_VA_FUNCS=TRUE"

  GCC:*_AFLCLANG_X64_CC_FLAGS = -DUSING_LTO "-DNO_MSABI_VA_FUNCS=TRUE" -fno-builtin

  # Must accompany -DTEST_WITH_LIBFUZZER: without the engine the binary passes
  # OSS-Fuzz's grep detection but nothing drives the entry point.
  GCC:*_AFLCLANG_X64_CC_FLAGS    = -DTEST_WITH_LIBFUZZER
  GCC:*_AFLCLANG_X64_DLINK_FLAGS = /usr/lib/libFuzzingEngine.a
