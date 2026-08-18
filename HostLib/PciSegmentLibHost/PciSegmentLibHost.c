/** @file PciSegmentLibHost.c
    Host-compatible PciSegmentLib — backed by a static 4KB config space
    buffer initialized to 0xFF (simulating unpopulated PCI config space).

    Reads return data from the virtual buffer. Writes update the buffer.
    All read-modify-write operations (Or, And, BitField, etc.) work through
    the basic Read/Write functions.

    Address encoding (PCI_SEGMENT_LIB_ADDRESS):
      Bits 63:32 = Segment, Bits 31:20 = Bus, Bits 19:15 = Device,
      Bits 14:12 = Function, Bits 11:0  = Register offset

    Copyright (c) 2026, HBFAplus Contributors. All rights reserved.
    SPDX-License-Identifier: BSD-2-Clause-Patent
**/

#include <Base.h>
#include <Library/BaseLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/DebugLib.h>
#include <Library/PciSegmentLib.h>

#define CONFIG_SPACE_SIZE  4096
#define REG_OFFSET(Addr)   ((UINTN)((Addr) & 0xFFF))

//
// Virtual PCI config space — 0xFF = "no device present"
//
STATIC UINT8   mConfigSpace[CONFIG_SPACE_SIZE];
STATIC BOOLEAN mInitialized = FALSE;

STATIC
VOID
EnsureInit (
  VOID
  )
{
  if (!mInitialized) {
    SetMem (mConfigSpace, CONFIG_SPACE_SIZE, 0xFF);
    mInitialized = TRUE;
  }
}

// ===========================================================================
// Register for Runtime Access (no-op on host)
// ===========================================================================

RETURN_STATUS
EFIAPI
PciSegmentRegisterForRuntimeAccess (
  IN UINTN  Address
  )
{
  return RETURN_SUCCESS;
}

// ===========================================================================
// 8-bit operations
// ===========================================================================

UINT8
EFIAPI
PciSegmentRead8 (
  IN UINTN  Address
  )
{
  EnsureInit ();
  return mConfigSpace[REG_OFFSET (Address)];
}

UINT8
EFIAPI
PciSegmentWrite8 (
  IN UINTN  Address,
  IN UINT8  Value
  )
{
  EnsureInit ();
  mConfigSpace[REG_OFFSET (Address)] = Value;
  return Value;
}

UINT8
EFIAPI
PciSegmentOr8 (
  IN UINTN  Address,
  IN UINT8  OrData
  )
{
  return PciSegmentWrite8 (Address, (UINT8)(PciSegmentRead8 (Address) | OrData));
}

UINT8
EFIAPI
PciSegmentAnd8 (
  IN UINTN  Address,
  IN UINT8  AndData
  )
{
  return PciSegmentWrite8 (Address, (UINT8)(PciSegmentRead8 (Address) & AndData));
}

UINT8
EFIAPI
PciSegmentAndThenOr8 (
  IN UINTN  Address,
  IN UINT8  AndData,
  IN UINT8  OrData
  )
{
  return PciSegmentWrite8 (Address, (UINT8)((PciSegmentRead8 (Address) & AndData) | OrData));
}

UINT8
EFIAPI
PciSegmentBitFieldRead8 (
  IN UINTN  Address,
  IN UINTN  StartBit,
  IN UINTN  EndBit
  )
{
  return BitFieldRead8 (PciSegmentRead8 (Address), StartBit, EndBit);
}

UINT8
EFIAPI
PciSegmentBitFieldWrite8 (
  IN UINTN  Address,
  IN UINTN  StartBit,
  IN UINTN  EndBit,
  IN UINT8  Value
  )
{
  return PciSegmentWrite8 (Address, BitFieldWrite8 (PciSegmentRead8 (Address), StartBit, EndBit, Value));
}

UINT8
EFIAPI
PciSegmentBitFieldOr8 (
  IN UINTN  Address,
  IN UINTN  StartBit,
  IN UINTN  EndBit,
  IN UINT8  OrData
  )
{
  return PciSegmentWrite8 (Address, BitFieldOr8 (PciSegmentRead8 (Address), StartBit, EndBit, OrData));
}

UINT8
EFIAPI
PciSegmentBitFieldAnd8 (
  IN UINTN  Address,
  IN UINTN  StartBit,
  IN UINTN  EndBit,
  IN UINT8  AndData
  )
{
  return PciSegmentWrite8 (Address, BitFieldAnd8 (PciSegmentRead8 (Address), StartBit, EndBit, AndData));
}

UINT8
EFIAPI
PciSegmentBitFieldAndThenOr8 (
  IN UINTN  Address,
  IN UINTN  StartBit,
  IN UINTN  EndBit,
  IN UINT8  AndData,
  IN UINT8  OrData
  )
{
  return PciSegmentWrite8 (Address, BitFieldAndThenOr8 (PciSegmentRead8 (Address), StartBit, EndBit, AndData, OrData));
}

// ===========================================================================
// 16-bit operations
// ===========================================================================

UINT16
EFIAPI
PciSegmentRead16 (
  IN UINTN  Address
  )
{
  UINT16  Val;

  EnsureInit ();
  CopyMem (&Val, &mConfigSpace[REG_OFFSET (Address)], sizeof (Val));
  return Val;
}

UINT16
EFIAPI
PciSegmentWrite16 (
  IN UINTN   Address,
  IN UINT16  Value
  )
{
  EnsureInit ();
  CopyMem (&mConfigSpace[REG_OFFSET (Address)], &Value, sizeof (Value));
  return Value;
}

UINT16
EFIAPI
PciSegmentOr16 (
  IN UINTN   Address,
  IN UINT16  OrData
  )
{
  return PciSegmentWrite16 (Address, (UINT16)(PciSegmentRead16 (Address) | OrData));
}

UINT16
EFIAPI
PciSegmentAnd16 (
  IN UINTN   Address,
  IN UINT16  AndData
  )
{
  return PciSegmentWrite16 (Address, (UINT16)(PciSegmentRead16 (Address) & AndData));
}

UINT16
EFIAPI
PciSegmentAndThenOr16 (
  IN UINTN   Address,
  IN UINT16  AndData,
  IN UINT16  OrData
  )
{
  return PciSegmentWrite16 (Address, (UINT16)((PciSegmentRead16 (Address) & AndData) | OrData));
}

UINT16
EFIAPI
PciSegmentBitFieldRead16 (
  IN UINTN  Address,
  IN UINTN  StartBit,
  IN UINTN  EndBit
  )
{
  return BitFieldRead16 (PciSegmentRead16 (Address), StartBit, EndBit);
}

UINT16
EFIAPI
PciSegmentBitFieldWrite16 (
  IN UINTN   Address,
  IN UINTN   StartBit,
  IN UINTN   EndBit,
  IN UINT16  Value
  )
{
  return PciSegmentWrite16 (Address, BitFieldWrite16 (PciSegmentRead16 (Address), StartBit, EndBit, Value));
}

UINT16
EFIAPI
PciSegmentBitFieldOr16 (
  IN UINTN   Address,
  IN UINTN   StartBit,
  IN UINTN   EndBit,
  IN UINT16  OrData
  )
{
  return PciSegmentWrite16 (Address, BitFieldOr16 (PciSegmentRead16 (Address), StartBit, EndBit, OrData));
}

UINT16
EFIAPI
PciSegmentBitFieldAnd16 (
  IN UINTN   Address,
  IN UINTN   StartBit,
  IN UINTN   EndBit,
  IN UINT16  AndData
  )
{
  return PciSegmentWrite16 (Address, BitFieldAnd16 (PciSegmentRead16 (Address), StartBit, EndBit, AndData));
}

UINT16
EFIAPI
PciSegmentBitFieldAndThenOr16 (
  IN UINTN   Address,
  IN UINTN   StartBit,
  IN UINTN   EndBit,
  IN UINT16  AndData,
  IN UINT16  OrData
  )
{
  return PciSegmentWrite16 (Address, BitFieldAndThenOr16 (PciSegmentRead16 (Address), StartBit, EndBit, AndData, OrData));
}

// ===========================================================================
// 32-bit operations
// ===========================================================================

UINT32
EFIAPI
PciSegmentRead32 (
  IN UINTN  Address
  )
{
  UINT32  Val;

  EnsureInit ();
  CopyMem (&Val, &mConfigSpace[REG_OFFSET (Address)], sizeof (Val));
  return Val;
}

UINT32
EFIAPI
PciSegmentWrite32 (
  IN UINTN   Address,
  IN UINT32  Value
  )
{
  EnsureInit ();
  CopyMem (&mConfigSpace[REG_OFFSET (Address)], &Value, sizeof (Value));
  return Value;
}

UINT32
EFIAPI
PciSegmentOr32 (
  IN UINTN   Address,
  IN UINT32  OrData
  )
{
  return PciSegmentWrite32 (Address, PciSegmentRead32 (Address) | OrData);
}

UINT32
EFIAPI
PciSegmentAnd32 (
  IN UINTN   Address,
  IN UINT32  AndData
  )
{
  return PciSegmentWrite32 (Address, PciSegmentRead32 (Address) & AndData);
}

UINT32
EFIAPI
PciSegmentAndThenOr32 (
  IN UINTN   Address,
  IN UINT32  AndData,
  IN UINT32  OrData
  )
{
  return PciSegmentWrite32 (Address, (PciSegmentRead32 (Address) & AndData) | OrData);
}

UINT32
EFIAPI
PciSegmentBitFieldRead32 (
  IN UINTN  Address,
  IN UINTN  StartBit,
  IN UINTN  EndBit
  )
{
  return BitFieldRead32 (PciSegmentRead32 (Address), StartBit, EndBit);
}

UINT32
EFIAPI
PciSegmentBitFieldWrite32 (
  IN UINTN   Address,
  IN UINTN   StartBit,
  IN UINTN   EndBit,
  IN UINT32  Value
  )
{
  return PciSegmentWrite32 (Address, BitFieldWrite32 (PciSegmentRead32 (Address), StartBit, EndBit, Value));
}

UINT32
EFIAPI
PciSegmentBitFieldOr32 (
  IN UINTN   Address,
  IN UINTN   StartBit,
  IN UINTN   EndBit,
  IN UINT32  OrData
  )
{
  return PciSegmentWrite32 (Address, BitFieldOr32 (PciSegmentRead32 (Address), StartBit, EndBit, OrData));
}

UINT32
EFIAPI
PciSegmentBitFieldAnd32 (
  IN UINTN   Address,
  IN UINTN   StartBit,
  IN UINTN   EndBit,
  IN UINT32  AndData
  )
{
  return PciSegmentWrite32 (Address, BitFieldAnd32 (PciSegmentRead32 (Address), StartBit, EndBit, AndData));
}

UINT32
EFIAPI
PciSegmentBitFieldAndThenOr32 (
  IN UINTN   Address,
  IN UINTN   StartBit,
  IN UINTN   EndBit,
  IN UINT32  AndData,
  IN UINT32  OrData
  )
{
  return PciSegmentWrite32 (Address, BitFieldAndThenOr32 (PciSegmentRead32 (Address), StartBit, EndBit, AndData, OrData));
}

// ===========================================================================
// Buffer operations
// ===========================================================================

UINTN
EFIAPI
PciSegmentReadBuffer (
  IN UINTN  StartAddress,
  IN UINTN  Size,
  OUT VOID  *Buffer
  )
{
  UINTN  Offset;

  if (Size == 0 || Buffer == NULL) {
    return Size;
  }

  EnsureInit ();
  Offset = REG_OFFSET (StartAddress);
  if (Offset + Size > CONFIG_SPACE_SIZE) {
    Size = CONFIG_SPACE_SIZE - Offset;
  }

  CopyMem (Buffer, &mConfigSpace[Offset], Size);
  return Size;
}

UINTN
EFIAPI
PciSegmentWriteBuffer (
  IN UINTN  StartAddress,
  IN UINTN  Size,
  IN VOID   *Buffer
  )
{
  UINTN  Offset;

  if (Size == 0 || Buffer == NULL) {
    return Size;
  }

  EnsureInit ();
  Offset = REG_OFFSET (StartAddress);
  if (Offset + Size > CONFIG_SPACE_SIZE) {
    Size = CONFIG_SPACE_SIZE - Offset;
  }

  CopyMem (&mConfigSpace[Offset], Buffer, Size);
  return Size;
}
