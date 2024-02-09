# Collection of my Ghidra scrtipts, used for ARM analysis.

I've built them as I learn Ghidra (slowly migrating from IDA), analyzing some bare ROM firmware built on TI's cc2640r2 stack.

Scripts there:

## arm-romtoram

This script goes thru compressed data table that being copied from ROM to RAM before application start.
See script header for instructions on how to find the table.

## ROM_Flash_JT

This script is useful to fill in the gaps in ROM support functions that goes into firmware part.
Again, see the script header for instructions on what to do before it feasible to run it.

## ArmImportSymbolsScript

Slight modification to default "`ImportSymbolsScript.py`" script, to work with symbols that points to hidden ROM.

## tool_elf2map.py

Not a ghidra script, but rather standalone tool to convert `*.symbols` and `*.elf` to output compatible with `ArmImportSymbolsScript` above.

Converts ROM symbols from f.e.
  `C:\ti\simplelink_cc2640r2_sdk_5_30_00_03\source\ti\blestack\rom\ble_rom_releases\cc26xx_r2\Final_Release`
