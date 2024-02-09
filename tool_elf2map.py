##
# Requires "pip install pwntools"
#
# Run either
#   tool_elf2map yourlibrary.elf
#   tool_elf2map yourlibrary.symbols
# to get corresponding
#   yourlibrary.elf.map.txt
#   yourlibrary.symbols.map.txt
# that you can import with ArmImportSymbolsScript afterwards.
#
#@author Anton Fedorov <datacompboy@gmail.com>
##
import sys
import pwnlib.elf.elf

input = sys.argv[1]
lib=pwnlib.elf.elf.ELF(input)

f=open(input+".map.txt", "w")
for name,fun in lib.functions.items():
  f.write("%s %x f\n" % (name, fun.address))

f.close()
