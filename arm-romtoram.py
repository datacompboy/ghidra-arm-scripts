# Run ROM to RAM copy and unpack.
#
# So far you should do before the script:
#   1. Define RAM region that will cover target addresses (e.g. 0x20000000...0x20100000 or whatever)
#   2. Find CopyROMtoRAM function, that looks like this:
#
#      ```
#      void CopyROMtoRAM(void)
#      {
#        undefined **ppuVar1;
#        
#        for (ppuVar1 = &ROMtoRAMtable; ppuVar1 < &ROMtoRAMtableEnd; ppuVar1 = ppuVar1 + 2) {
#          (*(code *)(&ROMtoRAM_Processors)[(byte)**ppuVar1])(*ppuVar1 + 1,ppuVar1[1]);
#        }
#        FUN_1001c414();
#        return;
#      }
#      ```
#
#   2. From the function you mark 'ROMtoRAMtable' and 'ROMtoRAMtableEnd' and ROMtoRAM_Processors.
#
#      - The ROMtoRAMtable is sequence of pointers, one in ROM and one in RAM
#      - The ROMtoRAM_Processors is sequence (in samples I have only 3) of processors, each receiving 2 pointers.
#        Processor 0 "unpack":
#          do .. while() loop,
#          that contains do  .. while (var < 8) loop
#          that starts with something like
#          ```
#          if ((ctrlByte & 1) == 0) {
#            src = srcPtr + 2;
#            length = (srcPtr[1] & 0xf) + 3;
#            window = ((uint)srcPtr[1] << 0x18) >> 0x1c | (uint)*srcPtr << 4;
#          ```
#
#        Processor 1 is just a proxy to memcpy:
#          memcpy(dst,src + 7,*(uint *)(src + 3));
#
#        Processor 2 is just a proxy to memset:
#          memset(dst,0,*(uint *)(src + 3));
#
#        If you found another processors, feel free to extend the table :)
#
#   3. Run the script and you'll get RAM replaced with the initial ROM bytes.
#
# TODO:
#   - Find the ROM2RAM func automatically
#   - Find the ROM2RAM tables automatically
#   - Validate unpackers table
#
#@author Anton Fedorov <datacompboy@gmail.com>
#@category ARM
# 

import array
import string

# Helpers
listing = currentProgram.getListing()
memory = currentProgram.getMemory()


def getUByte(address):
  return getByte(address)  & 0xFF


def forceWriteMem(dst, data):
  """Write `data` array starting address `dst`, making it initialized if necessary."""
  dstEnd = dst.add(len(data)-1)
  dstBlock = memory.getBlock(dst)
  if (not dstBlock.contains(dstEnd)):
    raise Exception("Whoops, memory got fragmented")

  if (not dstBlock.isInitialized()):
    # Split uninitialized RAM...
    if (dstBlock.contains(dstEnd.add(1))):
      memory.split(dstBlock, dstEnd.add(1))
    if (dstBlock.contains(dst.subtract(1))):
      memory.split(dstBlock, dst)
    memory.convertToInitialized(memory.getBlock(dst), 0)

  memory.setBytes(dst, data)


def getDefAddress(src):
  """Get address stored at address `src`, make it pointer if it uninitialized."""
  srcEntry = listing.getCodeUnitAt(src)
  if (not srcEntry.isDefined()):
    listing.createData(src, ghidra.program.model.data.PointerDataType())
    srcEntry = listing.getCodeUnitAt(src)
  return srcEntry.getValue()


def tryMakeArray(src, size):
  srcEntry = listing.getCodeUnitAt(src)
  if (not srcEntry.isDefined()):
    try:
      listing.createData(src, ghidra.program.model.data.ArrayDataType(ghidra.program.model.data.ByteDataType(), size, 1))
    except Exception as E:
      print("(W) Can't create array", E)


def tidyMemory():
  """Collapse sequential similar split blocks."""
  blocks = memory.getBlocks()
  blockId = 1
  while blockId < len(blocks):
    if ((blocks[blockId].getType() == ghidra.program.model.mem.MemoryBlockType.DEFAULT) and
        (blocks[blockId-1].getType() == ghidra.program.model.mem.MemoryBlockType.DEFAULT) and
        (blocks[blockId].isInitialized() == blocks[blockId-1].isInitialized()) and
        (blocks[blockId].getName()[-6:] == ".split") and
        (blocks[blockId-1].getEnd().add(1) == blocks[blockId].getStart())):
      memory.join(blocks[blockId-1], blocks[blockId])
      blocks = memory.getBlocks()
    else:
      name = blocks[blockId].getName()
      while name[-12:] == ".split.split":
        name = name[:-6]
      blocks[blockId].setName(name)
      blockId += 1


# Step 0: unpackers
def _memcpy(src):
  size = getInt(src.add(3))
  dataAddr = src.add(7)
  return (getBytes(dataAddr, size), 7 + size)

def _memzero(src):
  size = getInt(src.add(3))
  return (array.array('b', [0]*size), 7)

def _unpack(src):
  res = []
  _start = src
  while True:
    control = getUByte(src)
    src = src.add(1)
    for i in range(8):
      if control & 0x01 == 1:
        res.append(getByte(src)) # Signed
        src = src.add(1)
      else:
        offset = (getUByte(src) << 4) | (getUByte(src.add(1)) >> 4)
        size = (getUByte(src.add(1)) & 0x0F) + 3
        src = src.add(2)
        if offset == 0xFFF:
          return (array.array('b', res), src.getOffset()-_start.getOffset())
        if (size == 18):
          extra = getUByte(src)
          src = src.add(1)
          if (extra & 0x80 != 0):
            extra = extra & 0x7F + getUByte(src)
            src = src.add(1)
          size = size + extra
        offset = - 1 - offset
        for k in range(size):
          res.append(res[offset])
      control = control >> 1
#

# Step 1: get ROMtoRAMtable
ROMtoRAMtable = getSymbol("ROMtoRAMtable", None)
if (ROMtoRAMtable is None):
    raise Exception("ROMtoRAMtable is not defined")
    

ROMtoRAMtableEnd = getSymbol("ROMtoRAMtableEnd", None)
if (ROMtoRAMtableEnd is None):
    raise Exception("ROMtoRAMtableEnd is not defined")

# Step 2: get decoders table
decoders = [
  _unpack,
  _memcpy,
  _memzero
]

# Step 3: process
# 3.1: make table addresses
entry = ROMtoRAMtable.address
while (entry < ROMtoRAMtableEnd.address):
  src = getDefAddress(entry)
  dst = getDefAddress(entry.add(4))
  unpackedData, processedLen = decoders[getUByte(src)](src.add(1))
  forceWriteMem(dst, unpackedData)
  tryMakeArray(src, processedLen)
  entry = entry.add(8)

# Step 4: ...
tidyMemory()

# Step 5: PROFIT
print("Unpack complete, good luck")
