# genmc - Display Hex-Rays Microcode

genmc is an IDAPython script/plugin hybrid that displays Hexrays decompiler
microcode, which an help in developing microcode plugins.

By running the code as a script within IDA, a Python shell command becomes
available which, after typing "install_plugin()", copies the script to
$HOME/.idapro/plugins or %APPDATA%Hex-Rays/IDA Pro/plugins.

With the script installed into the plugins folder, it can be invoked from
the plugins menu or by using the hotkey 'Ctrl-Shift-M'.

IDA and decompilers >= 7.3 are required.

Based on code/ideas from:
- vds13.py from Hexrays SDK
- https://github.com/RolfRolles/HexRaysDeob
- https://github.com/NeatMonster/MCExplorer