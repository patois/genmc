# genmc - Display Hex-Rays Microcode
#
# Requires IDA and decompiler(s) >= 7.3
#
# Based on code/ideas from:
# - https://github.com/RolfRolles/HexRaysDeob
# - https://github.com/NeatMonster/MCExplorer

__author__ = "Dennis Elser"

# -----------------------------------------------------------------------------
import os

import ida_idaapi
import ida_bytes
import ida_range
import ida_kernwin
import ida_hexrays
import ida_funcs
import ida_diskio
import ida_ida
import shutil
import errno

# -----------------------------------------------------------------------------
def is_plugin():
    """returns True if this script is executed from within an IDA plugins
    directory, False otherwise."""
    return "__plugins__" in __name__

# -----------------------------------------------------------------------------
SELF = __file__
def install_plugin():
    """Installs script to IDA userdir as a plugin"""
    if is_plugin():
        ida_kernwin.msg("Command not available. Plugin already installed.\n")
        return False

    src = SELF
    base = os.path.join(
        ida_diskio.get_user_idadir(),
        "plugins")
    dst = os.path.join(base, genmc.wanted_name+".py")
    if os.path.isfile(dst):
        btnid = ida_kernwin.ask_yn(ida_kernwin.ASKBTN_NO, "File exists. Replace?")
        if btnid is not ida_kernwin.ASKBTN_YES:
            return False
    ida_kernwin.msg("Copying script from \"%s\" to \"%s\"..." % (src, dst))
    if not os.path.exists(base):
        try:
            os.path.makedirs(base)
        except OSError as e:
            if e.errno != errno.EEXIST:
                ida_kernwin.msg("failed (mkdir)!\n")
                return False
    try:
        shutil.copy(src, dst)
    except:
        ida_kernwin.msg("failed (copy)!\n")
        return False
    ida_kernwin.msg("done!\n")
    return True

# -----------------------------------------------------------------------------
def is_ida_version(requested):
    """Checks minimum required IDA version."""
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
    """Checks whether script is compatible with current IDA and
    decompiler versions."""
    min_ida_ver = "7.3"
    return is_ida_version(min_ida_ver) and ida_hexrays.init_hexrays_plugin()

# -----------------------------------------------------------------------------
class printer_t(ida_hexrays.vd_printer_t):
    """Converts microcode output to an array of strings."""
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
    """Creates a widget that displays Hex-Rays microcode."""
    def Create(self, title, lines = []):
        title = "View Microcode - %s" % title
        if not ida_kernwin.simplecustviewer_t.Create(self, title):
            return False

        for line in lines:
            self.AddLine(line)
        return True

# -----------------------------------------------------------------------------
def ask_desired_maturity():
    """Displays a dropdown list control which lets the user
    choose a maturity level of the microcode to generate."""

    maturity_levels = [
    ["MMAT_GENERATED", ida_hexrays.MMAT_GENERATED],
    ["MMAT_PREOPTIMIZED", ida_hexrays.MMAT_PREOPTIMIZED],
    ["MMAT_LOCOPT", ida_hexrays.MMAT_LOCOPT],
    ["MMAT_CALLS", ida_hexrays.MMAT_CALLS],
    ["MMAT_GLBOPT1", ida_hexrays.MMAT_GLBOPT1],
    ["MMAT_GLBOPT2", ida_hexrays.MMAT_GLBOPT2],
    ["MMAT_GLBOPT3", ida_hexrays.MMAT_GLBOPT3],
    ["MMAT_LVARS", ida_hexrays.MMAT_LVARS]]

    class MaturityForm(ida_kernwin.Form):
        def __init__(self):
            form = """%s
             <Maturity level:{mat_lvl}>
             <##MBA Flags (currently unsupported)##MBA_SHORT:{flags_short}>{chkgroup_flags}>
             """ % genmc.wanted_name

            dropdown_ctl = ida_kernwin.Form.DropdownListControl(
                [text for text, _ in maturity_levels])
            chk_ctl = ida_kernwin.Form.ChkGroupControl(("flags_short",))

            controls = {"mat_lvl": dropdown_ctl,
            "chkgroup_flags": chk_ctl}

            ida_kernwin.Form.__init__(self, form, controls)

    form = MaturityForm()
    form, args = form.Compile()
    ok = form.Execute()
    mmat = None
    text = None
    if ok == 1:
        text, mmat = maturity_levels[form.mat_lvl.value]
    form.Free()
    return (text, mmat)

# -----------------------------------------------------------------------------
def show_microcode():
    """Generates and displays microcode for an address range.
    An address range can be a selection of code or that of
    the current function."""

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
    return (True,
        "Successfully generated microcode for 0x%s..0x%s\n" % (addr_fmt % sea, addr_fmt % eea))

# -----------------------------------------------------------------------------
def create_mc_widget():
    """Checks minimum requirements for the script/plugin to be able to run.
    Displays microcode or in case of failure, displays error message.
    This function acts as the main entry point that is invoked if the
    code is run as a script or as a plugin."""
    if not is_compatible():
        ida_kernwin.msg("%s: Unsupported IDA / Hex-rays version\n" % (genmc.wanted_name))
        return False
    success, message = show_microcode()
    output = ida_kernwin.msg if success else ida_kernwin.warning
    output("%s: %s\n" % (genmc.wanted_name, message))
    return success

# -----------------------------------------------------------------------------
class genmc(ida_idaapi.plugin_t):
    """Class that is required for the code to be recognized as
    a plugin by IDA."""
    flags = 0
    comment = "Display microcode"
    help = comment
    wanted_name = 'genmc'
    wanted_hotkey = 'Ctrl-Shift-M'

    def init(self):
        return (ida_idaapi.PLUGIN_OK if
            is_compatible() else ida_idaapi.PLUGIN_SKIP)

    def run(self, arg):
        create_mc_widget()

    def term(self):
        pass

# -----------------------------------------------------------------------------
def PLUGIN_ENTRY():
    """Entry point of this code if launched as a plugin."""
    return genmc()

# -----------------------------------------------------------------------------
def SCRIPT_ENTRY():
    """Entry point of this code if launched as a script."""
    if not is_plugin():
        ida_kernwin.msg(("%s: Available commands:\n"
            "[+] \"install_plugin()\" - install script to ida_userdir/plugins\n") % (
            genmc.wanted_name))
        create_mc_widget()
        return True
    return False

# -----------------------------------------------------------------------------
SCRIPT_ENTRY()