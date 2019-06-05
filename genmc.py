# genmc - Display Hex-Rays Microcode
#
# Requires IDA and decompiler(s) >= 7.3
#
# Based on code/ideas from:
# - https://github.com/RolfRolles/HexRaysDeob
# - https://github.com/NeatMonster/MCExplorer

import os

import ida_idaapi
import ida_bytes
import ida_range
import ida_kernwin
import ida_hexrays
import ida_funcs
import ida_diskio
import ida_ida


__author__ = "Dennis Elser"


LEVELS = [
["MMAT_GENERATED",ida_hexrays.MMAT_GENERATED],
["MMAT_PREOPTIMIZED",ida_hexrays.MMAT_PREOPTIMIZED],
["MMAT_LOCOPT",ida_hexrays.MMAT_LOCOPT],
["MMAT_CALLS",ida_hexrays.MMAT_CALLS],
["MMAT_GLBOPT1",ida_hexrays.MMAT_GLBOPT1],
["MMAT_GLBOPT2",ida_hexrays.MMAT_GLBOPT2],
["MMAT_GLBOPT3",ida_hexrays.MMAT_GLBOPT3],
["MMAT_LVARS",ida_hexrays.MMAT_LVARS]]

try:
    VIEWERS
except:
    VIEWERS = []

# -----------------------------------------------------------------------------
def is_ida_version(requested):
    rv = requested.split(".")
    kv = ida_kernwin.get_kernel_version().split(".")

    count = min(len(rv), len(kv))
    if not count:
        return False

    for i in xrange(count):
        if int(kv[i]) < int(rv[i]):
            return False
    return True

# -----------------------------------------------------------------------------
def is_compatible():
    min_ida_ver = "7.3"
    return is_ida_version(min_ida_ver) and ida_hexrays.init_hexrays_plugin()

# -----------------------------------------------------------------------------
class printer_t(ida_hexrays.vd_printer_t):
    def __init__(self, *args):
        ida_hexrays.vd_printer_t.__init__(self)
        self.mc = []

    def get_mc(self):
        return self.mc

    def _print(self, indent, line):
        self.mc.append(line)
        return 1

# -----------------------------------------------------------------------------
class microcode_viewer_t(ida_kernwin.simplecustviewer_t):
    def Create(self, title, lines = []):
        title = "View Microcode - %s" % title
        if not ida_kernwin.simplecustviewer_t.Create(self, title):
            return False

        for line in lines:
            self.AddLine(line)
        return True

# -----------------------------------------------------------------------------
def ask_desired_maturity():
    class MaturityForm(ida_kernwin.Form):
        def __init__(self):
            ctrl = ida_kernwin.Form.DropdownListControl([text for text, _ in LEVELS])
            form = """Select maturity level
             <Select maturity level:{ctrl}>"""
            ida_kernwin.Form.__init__(self, form, {"ctrl": ctrl})

    form = MaturityForm()
    form, args = form.Compile()
    ok = form.Execute()
    mmat = None
    text = None
    if ok == 1:
        text, mmat = LEVELS[form.ctrl.value]
    form.Free()
    return (text, mmat)

# -----------------------------------------------------------------------------
def show_microcode():
    global VIEWERS

    sel, sea, eea = ida_kernwin.read_range_selection(None)
    pfn = ida_funcs.get_func(ida_kernwin.get_screen_ea())
    if not sel and not pfn:
        return (False, "Position cursor within a function or select range")

    if not sel and pfn:
        sea = pfn.start_ea
        eea = pfn.end_ea

    addr_fmt = "%016x" if ida_ida.inf_is_64bit() else "%08x"
    F = ida_bytes.get_flags(sea)
    if not ida_bytes.is_code(F):
        return (False, "The selected range must start with an instruction")

    text, mmat = ask_desired_maturity()
    if text is None and mmat is None:
        return (False, "Cancelled")

    hf = ida_hexrays.hexrays_failure_t()
    mbr = ida_hexrays.mba_ranges_t()
    mbr.ranges.push_back(ida_range.range_t(sea, eea))
    ml = ida_hexrays.mlist_t()
    mba = ida_hexrays.gen_microcode(mbr, hf, ml, ida_hexrays.DECOMP_WARNINGS, mmat)
    if not mba:
        return (False, "0x%s: %s" % (addr_fmt % hf.errea, hf.str))

    vp = printer_t()
    mba._print(vp)
    mcv = microcode_viewer_t()
    if not mcv.Create("0x%s-0x%s (%s)" % (addr_fmt % sea, addr_fmt % eea, text), vp.get_mc()):
        return (False, "Error creating viewer")

    mcv.Show()
    VIEWERS.append(mcv)
    return (True,
        "Successfully generated microcode for 0x%s..0x%s\n" % (addr_fmt % sea, addr_fmt % eea))

# -----------------------------------------------------------------------------
def create_mc_widget():
    if not is_compatible():
        ida_kernwin.msg("%s: Unsupported IDA / Hex-rays version\n" % (genmc.wanted_name))
        return False
    success, message = show_microcode()
    output = ida_kernwin.msg if success else ida_kernwin.warning
    output("%s: %s\n" % (genmc.wanted_name, message))
    return success

# -----------------------------------------------------------------------------
class genmc(ida_idaapi.plugin_t):
    flags = 0
    comment = "Display microcode"
    help = comment
    wanted_name = 'genmc'
    wanted_hotkey = 'Ctrl-Shift--'

    def init(self):
        return (ida_idaapi.PLUGIN_OK if
            is_compatible() else ida_idaapi.PLUGIN_SKIP)

    def run(self, arg):
        create_mc_widget()

    def term(self):
        pass

# -----------------------------------------------------------------------------
def PLUGIN_ENTRY():   
    return genmc()

# -----------------------------------------------------------------------------
def SCRIPT_ENTRY():
    if "__plugins__" not in __name__:
        """
        ida_plugins_dir = ida_diskio.idadir("plugins")
        usr_plugins_dir = os.path.join(ida_diskio.get_user_idadir(), "plugins")
        ida_kernwin.msg("This script may also be installed as a plugin to\n 1.) %s\n 2.) %s\n" % (
            ida_plugins_dir,
            usr_plugins_dir))
        """
        create_mc_widget()
    return

# -----------------------------------------------------------------------------
SCRIPT_ENTRY()