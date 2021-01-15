# genmc - Display Hex-Rays Microcode

genmc is an IDAPython script/plugin hybrid that displays Hexrays decompiler
microcode, which can help in developing microcode plugins.

![genmc animated gif](/rsrc/genmc.gif?raw=true)

## Installation / Usage
By running the code as a script within IDA, a Python shell command becomes
available which, after typing "install_plugin()", copies the script to
$HOME/.idapro/plugins or %APPDATA%Hex-Rays/IDA Pro/plugins.

With the script installed into the plugins folder, it can be invoked from
the plugins menu or by using the hotkey 'Ctrl-Shift-M'.

IDA and decompilers >= 7.3 are required.

This IDAPython project is compatible with Python3. For compatibility with older versions of IDA, you may want to check out the Python2 branch of this project.

## Keyboard shortcuts/modifiers:
With the microcode viewer focussed:

- 'g': display microcode graph
- 'i': display graph for current micro-instruction
- 'Shift': holding this modifier will create floating graph widgets (instead of using the default docking behavior)

## Credits:
- https://github.com/RolfRolles/ for his Microcode Explorer plugin whose original ideas and code this script is heavily based on (https://github.com/RolfRolles/HexRaysDeob). Full credit for most of the code and ideas in its original form belongs to Rolf. Check out his related blog post on Hexblog: http://www.hexblog.com/?p=1248 
- https://github.com/NeatMonster/ for porting of the Microcode Explorer C++ code to IDAPython using ctypes when Python bindings for HexRays' microcode were not available yet (https://github.com/NeatMonster/MCExplorer).
- https://github.com/icecr4ck/ for porting MCExplorer for IDAPython from 7.x to 7.3

Please consider using [Lucid - An Interactive Hex-Rays Microcode Explorer](https://github.com/gaasedelen/lucid), instead!
