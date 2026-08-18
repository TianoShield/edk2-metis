/** @file HbfaplusTestFramework.h
    Shared lightweight test framework for HBFAplus unit tests.

    Provides common test macros and counters so every test file in the project
    uses one consistent set of assertion / reporting primitives.

    Usage:
      1. Include this header.
      2. Declare storage once per translation unit:
           HBFAPLUS_TEST_STORAGE;
      3. Write test functions using TEST_BEGIN / TEST_END / ASSERT_* macros.
      4. In RunTestHarness, call HBFAPLUS_TEST_SUMMARY() after all tests run.
         It will exit(1) on failures.

    Macro reference:
      TEST_BEGIN(name)              - Start a named test case
      TEST_END()                    - Mark current test passed
      ASSERT_TRUE(cond)            - Fail + return if condition is false
      ASSERT_FALSE(cond)           - Fail + return if condition is true
      ASSERT_EQ(expected, actual)  - Fail + return if values differ
      ASSERT_NULL(ptr)             - Fail + return if pointer is non-NULL
      ASSERT_NOT_NULL(ptr)         - Fail + return if pointer is NULL
      ASSERT_MEM_EQ(e, a, n)      - Fail + return if n bytes differ
      ASSERT_STATUS(expected, s)   - Fail + return if EFI_STATUS differs
      HBFAPLUS_TEST_STORAGE        - Declare required global counters
      HBFAPLUS_TEST_SUMMARY()      - Print summary and exit(1) on failures

    Copyright (c) 2025, HBFAplus Contributors. All rights reserved.
    SPDX-License-Identifier: BSD-2-Clause-Patent
**/

#ifndef HBFAPLUS_TEST_FRAMEWORK_H_
#define HBFAPLUS_TEST_FRAMEWORK_H_

#include <stdio.h>
#include <stdlib.h>

//=============================================================================
// Test counters — each test translation unit must define storage exactly once
// using the HBFAPLUS_TEST_STORAGE macro.
//=============================================================================

///
/// Declare global test counters.  Place this macro at file scope
/// in exactly one .c file per test executable.
///
#define HBFAPLUS_TEST_STORAGE  \
  STATIC UINTN  gTestsRun    = 0; \
  STATIC UINTN  gTestsPassed = 0; \
  STATIC UINTN  gTestsFailed = 0

//=============================================================================
// Test lifecycle macros
//=============================================================================

///
/// Begin a named test case.  Increments the run counter.
///
#define TEST_BEGIN(name) \
  do { \
    printf ("[TEST] %s\n", name); \
    gTestsRun++; \
  } while (0)

///
/// Mark the current test as passed.  Call at the end of test functions that
/// did not hit any ASSERT_* failure.
///
#define TEST_END() \
  do { \
    gTestsPassed++; \
    printf ("[PASS]\n\n"); \
  } while (0)

//=============================================================================
// Assertion macros
//
// Each assertion macro:
//   - Prints  [FAIL] file:line  on failure.
//   - Increments gTestsFailed.
//   - Returns from the calling function (void) so the test stops immediately.
//=============================================================================

///
/// Assert condition is true.
///
#define ASSERT_TRUE(cond) \
  do { \
    if (!(cond)) { \
      printf ("[FAIL] %s:%d: ASSERT_TRUE(%s) failed\n", \
              __FILE__, __LINE__, #cond); \
      gTestsFailed++; \
      return; \
    } \
  } while (0)

///
/// Assert condition is false.
///
#define ASSERT_FALSE(cond) \
  do { \
    if (cond) { \
      printf ("[FAIL] %s:%d: ASSERT_FALSE(%s) failed\n", \
              __FILE__, __LINE__, #cond); \
      gTestsFailed++; \
      return; \
    } \
  } while (0)

///
/// Assert two scalar values are equal.
///
#define ASSERT_EQ(expected, actual) \
  do { \
    if ((expected) != (actual)) { \
      printf ("[FAIL] %s:%d: ASSERT_EQ failed: expected 0x%llx, got 0x%llx\n", \
              __FILE__, __LINE__, \
              (unsigned long long)(expected), \
              (unsigned long long)(actual)); \
      gTestsFailed++; \
      return; \
    } \
  } while (0)

///
/// Assert pointer is NULL.
///
#define ASSERT_NULL(ptr) \
  do { \
    if ((ptr) != NULL) { \
      printf ("[FAIL] %s:%d: ASSERT_NULL(%s) failed — got %p\n", \
              __FILE__, __LINE__, #ptr, (VOID *)(ptr)); \
      gTestsFailed++; \
      return; \
    } \
  } while (0)

///
/// Assert pointer is non-NULL.
///
#define ASSERT_NOT_NULL(ptr) \
  do { \
    if ((ptr) == NULL) { \
      printf ("[FAIL] %s:%d: ASSERT_NOT_NULL(%s) failed\n", \
              __FILE__, __LINE__, #ptr); \
      gTestsFailed++; \
      return; \
    } \
  } while (0)

///
/// Assert two memory regions of @p size bytes are identical.
///
#define ASSERT_MEM_EQ(expected, actual, size) \
  do { \
    if (CompareMem ((expected), (actual), (size)) != 0) { \
      printf ("[FAIL] %s:%d: ASSERT_MEM_EQ failed\n", \
              __FILE__, __LINE__); \
      gTestsFailed++; \
      return; \
    } \
  } while (0)

///
/// Assert an EFI_STATUS matches expected.
///
#define ASSERT_STATUS(expected, actual) \
  do { \
    if ((expected) != (actual)) { \
      printf ("[FAIL] %s:%d: ASSERT_STATUS failed: expected %llx, got %llx\n", \
              __FILE__, __LINE__, \
              (unsigned long long)(expected), \
              (unsigned long long)(actual)); \
      gTestsFailed++; \
      return; \
    } \
  } while (0)

//=============================================================================
// Summary macro — call once at end of RunTestHarness
//=============================================================================

///
/// Print test results and exit(1) on any failures.
///
#define HBFAPLUS_TEST_SUMMARY() \
  do { \
    printf ("=== Test Summary ===\n"); \
    printf ("Tests Run:    %lu\n", (unsigned long)gTestsRun); \
    printf ("Tests Passed: %lu\n", (unsigned long)gTestsPassed); \
    printf ("Tests Failed: %lu\n", (unsigned long)gTestsFailed); \
    if (gTestsFailed > 0) { \
      printf ("\n*** FAILURES DETECTED ***\n"); \
      exit (1); \
    } else { \
      printf ("\n*** ALL TESTS PASSED ***\n"); \
    } \
  } while (0)

#endif /* HBFAPLUS_TEST_FRAMEWORK_H_ */
