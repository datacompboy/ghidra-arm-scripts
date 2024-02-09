# Run ROM to RAM copy and unpack.
#
#@author Anton Fedorov <datacompboy@gmail.com>
#@category ARM
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
#   - Merge sequental memory blocks if any created
#   - Mark src data as arrays
#

from ghidra.program.model.symbol.SourceType import *
import array
import string
listing = currentProgram.getListing()
memory = currentProgram.getMemory()

# Step 0: unpackers
def getUByte(address):  return getByte(address)  & 0xFF
def _memcpy(src):
  size = getInt(src.add(3))
  dataAddr = src.add(7)
  return getBytes(dataAddr, size)

def _memzero(src):
  size = getInt(src.add(3))
  return array.array('b', [0]*size)

def _unpack(src):
  res = []
  while True:
    control = getUByte(src)
    src = src.add(1)
    for i in range(8):
      if control & 0x01 == 1:
        res.append(getByte(src)) # Signed
        src = src.add(1)
      else:
        offset = (getUByte(src) << 4) | (getUByte(src.add(1)) >> 4)
        if offset == 0xFFF:
          return array.array('b', res)
        size = (getUByte(src.add(1)) & 0x0F) + 3
        src = src.add(2)
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
  srcEntry = listing.getCodeUnitAt(entry)
  if (not srcEntry.isDefined()):
    listing.createData(entry, ghidra.program.model.data.PointerDataType())
    srcEntry = listing.getCodeUnitAt(entry)
  src = srcEntry.getValue()
  #
  dstEntry = listing.getCodeUnitAt(entry.add(4))
  if (not dstEntry.isDefined()):
    listing.createData(entry.add(4), ghidra.program.model.data.PointerDataType())
    dstEntry = listing.getCodeUnitAt(entry.add(4))
  dst = dstEntry.getValue()
  #
  unpackedData = decoders[getUByte(src)](src.add(1))

  # print("Unpacked into: ", unpackedData)
  # Store unpackedData array into memory, by making it initialized... 
  dstEnd = dst.add(len(unpackedData)-1)
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
  memory.setBytes(dst, unpackedData)
  #
  entry = entry.add(8)

# Step 4: PROFIT
print("Unpack complete, good luck")
