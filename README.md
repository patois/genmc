# genmc - Display Hex-Rays Microcode

genmc is an IDAPython script/plugin hybrid that displays Hexrays decompiler
microcode, which can help in developing microcode plugins.

By running the code as a script within IDA, a Python shell command becomes
available which, after typing "install_plugin()", copies the script to
$HOME/.idapro/plugins or %APPDATA%Hex-Rays/IDA Pro/plugins.

With the script installed into the plugins folder, it can be invoked from
the plugins menu or by using the hotkey 'Ctrl-Shift-M'.

Microcode viewer keyboard shortcuts:
- 'g': display microcode graph
- 'i': display graph for current microinstruction
- 'Shift': holding this key will create floating graphs

IDA and decompilers >= 7.3 are required.

Based on code/ideas from:
- vds13.py from Hexrays SDK
- https://github.com/RolfRolles/HexRaysDeob
- https://github.com/NeatMonster/MCExplorer

![genmc animated gif](/rsrc/genmc.gif?raw=true)