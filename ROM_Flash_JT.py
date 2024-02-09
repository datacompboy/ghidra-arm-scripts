# Read "rom_init.c" file from TI BLE Stack and rename all found missing entries.
#
# To use the script:
#
#  - Import rom symbols for convenience & validation
#  - Find and define the "ROM_Flash_JT" symbol at the beginning of the table
#    You can find the table by looking for table containing pointers to words 2800, 2801, 2A05, 2803 (in this order)
#    or back-reference from HCI_bm_alloc or LL_ConnActive or any other ROM function that listed there
#  - Then run the script and give the path to your version of
#        C:\ti\simplelink_cc2640r2_sdk_5_30_00_03\source\ti\blestack\rom\r2\rom_init.c
#  - ... enjoy
#
#@author Anton Fedorov <datacompboy@gmail.com>
#@category ARM
#

import re

functionManager = currentProgram.getFunctionManager()
symbolTable = currentProgram.getSymbolTable()
listing = currentProgram.getListing()

def getDefAddress(src):
  """Get address stored at address `src`, make it pointer if it uninitialized."""
  srcEntry = listing.getCodeUnitAt(src)
  if (not srcEntry.isDefined()):
    listing.createData(src, ghidra.program.model.data.PointerDataType())
    srcEntry = listing.getCodeUnitAt(src)
  return srcEntry.getValue()

def isAddressLabelDefault(name):
  return name.split('_', 1)[0] in {"DAT", "WORD", "FUN", "LAB"}  # Hack for now

def isAddressIsLabel(name):
  return name[:4] == "LAB_"

ROM_Flash_JT = getSymbol("ROM_Flash_JT", None)
if (ROM_Flash_JT is None):
    raise Exception("ROM_Flash_JT is not defined")

f = askFile("Path to rom_init.c", "Parse rom_init.c")

matcher = re.compile(r'\(uint32\)[&]?(\w+),\W+// ROM_JT_OFFSET\[(\d+)\]')

# Before defining the symbols it's better to try to validate that we have any other defined
discovered = []
existing = 0
total = 0

for line in file(f.absolutePath):  # note, cannot use open(), since that is in GhidraScript
  match = matcher.match(line.strip())
  if not match:
    continue

  name = match.group(1)
  idx = int(match.group(2))

  src = ROM_Flash_JT.address.add(idx * 4)
  refAddr = getDefAddress(src)
  total += 1

  symbol = symbolTable.getPrimarySymbol(refAddr)
  if symbol.isDynamic() or symbol.getName()[-2:]=="+1":  # Get main function address
    refAddr = refAddr.subtract(refAddr.getOffset()&1)
    symbol = symbolTable.getPrimarySymbol(refAddr)

  if (symbol is not None) and (not isAddressLabelDefault(symbol.getName())) and (symbol.getName() == name):
    existing += 1
  else:
    yetlabel = symbol is None or isAddressIsLabel(symbol.getName())
    discovered.append( (name, refAddr, yetlabel) )


# Check that we know enough to be sure it's correct table
if total < 100 or existing < total/10:
  raise Exception("Existing entries less than 10% of the table, something's wrong")

for name, addr, yetlabel in discovered:
  print("To define: "+name+" at "+str(addr)+" ("+str(yetlabel)+")")
  func = functionManager.getFunctionAt(addr)
  if func:
    func.setName(name, ghidra.program.model.symbol.SourceType.IMPORTED)
  else:
    if yetlabel:
      func = createFunction(addr, name)
      if str(currentProgram.getListing().getCodeUnitAt(addr)) == "?? ??":
        currentProgram.getListing().createData(addr, ghidra.program.model.data.WordDataType())
    else:
      createLabel(addr, name, False)
