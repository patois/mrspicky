import idaapi
import idautils
import idc

# MrsPicky - An IDAPython decompiler script that helps auditing calls
# to the memcpy() and memmove() functions.
# 
# This scripts mainly exists for learning purposes on how to use the
# Hex-Rays decompiler API to process decompiled code. Its purpose is to
# create a list of memcpy() function calls and to identify and point out
# potentially dangerous ones.
# 
# It will display a list of identified calls that can be and is meant to
# be searched, sorted and filtered interactively using IDA's built-in
# filtering features. Double clicking a list's entry will show a respective
# call, in the currently active IDA or Decompiler views.
# 
# In cases where a memcpy(dst, src, n) "n" argument can be resolved statically
# by this script, the resulting list will have a "max n" tab that reflects
# the maximum number of bytes that a destination buffer "dst" can be written to.
# In other words: any number larger than that will corrupt whatever follows the
# current stack frame, which usually is a return address.
# 
# There is also a "problems" tab on the resulting list, which may contain any of
# the following keywords:
# 
#   * "memcorr" - indicates a confirmed memory corruption
#   * "argptr"  - the "dst" pointer points beyond the local stack frame
#                 (this may not actually be a problem per se but...)
# 
# The script's code is heavily commented so I would like to invite you to play
# around with it and customize it.
# 
# For further help, check out the include header file "hexrays.hpp" that comes
# with the Hex-Rays decompiler SDK and the HRDevHelper plugin on my github.
# 
# /*
# * ----------------------------------------------------------------------------
# * "THE BEER-WARE LICENSE" (Revision 42):
# * Dennis Elser wrote this file. As long as you retain this notice you
# * can do whatever you want with this stuff. If we meet some day, and you think
# * this stuff is worth it, you can buy me a beer in return.
# * ----------------------------------------------------------------------------
# */

__author__ = "Dennis Elser"

MEMCPY_FAM = ["memcpy", "memmove"]

ID_NA = "."

# -----------------------------------------------------------------------------
class MemcpyLocation():
    """Internal data that's represented by IDA's listview (Wchooser")
    """
    def __init__(self, ea, name, dst, src, n, dst_type, n_max, problems):
        self.ea = ea
        self.name = name
        self.dst = dst
        self.src = src
        self.n = n
        self.dst_type = dst_type
        self.n_max = n_max
        self.problems = problems

# -----------------------------------------------------------------------------
class MrsPickyListView(idaapi.Choose):
    """Listview that displays results to the user
    """
    def __init__(self, title, flags=0, width=None, height=None, embedded=False, modal=False):
        idaapi.Choose.__init__(
            self,
            title,
            [ ["caller", 20 | idaapi.CHCOL_FNAME],
            ["function", 8 | idaapi.CHCOL_FNAME],
            ["dst", 8],
            ["src", 8],
            ["n", 8 | idaapi.CHCOL_DEC],
            ["dst type", 8],
            ["max n", 8 | idaapi.CHCOL_DEC],
            ["problems", 20] ],
            flags = flags,
            width = width,
            height = height,
            embedded = embedded)
        self.items = []

    def OnClose(self):
        """empty internal data if view is closed
        """
        self.items = []

    def OnSelectLine(self, n):
        """navigate to code location
        """
        idaapi.jumpto(self.items[n].ea)

    def OnGetLine(self, n):
        """generate textual representation
        """
        return self._make_listview_entry(n)

    def OnGetSize(self):
        """get number of listview items
        """
        n = len(self.items)
        return n

    def feed(self, data):
        """add entry to listview dynamically
        """
        for item in data:
            self.items.append(item)
        self.Refresh()
        return

    def _make_listview_entry(self, n):
        """generate textual representation of a single
        line"""
        ea = "%s" % idc.get_func_off_str(self.items[n].ea)
        name = "%s" % self.items[n].name
        dst = self.items[n].dst
        src = self.items[n].src

        _n = self.items[n].n
        _n = _n if type(_n) == str else str(_n)

        max_n = self.items[n].n_max
        max_n = max_n if type(max_n) == str else str(max_n)
        dst_type = self.items[n].dst_type
        return [ea, name, dst, src, _n, dst_type, max_n, ", ".join(self.items[n].problems)]

# -----------------------------------------------------------------------------
class func_parser_t(idaapi.ctree_visitor_t):
    def __init__(self, cfunc):
        idaapi.ctree_visitor_t.__init__(self, idaapi.CV_FAST)
        self.cfunc = cfunc
        self.data = []
        return

    # for every expression / cexpr_t of the AST
    def visit_expr(self, e):
        # if expression type is call
        if e.op == idaapi.cot_call:
            name = idaapi.tag_remove(e.x.print1(None))
            # and if the function name is supported
            if name in MEMCPY_FAM:
                # parse the call
                self._parse_memcpy(e)
        return 0

    def _parse_memcpy(self, e):
        # get memcpy func args
        args = e.a # carglist_t

        # check number of args
        if args.size() != 3: # len(args) works as well
            return False

        # init some vars
        n_value = ID_NA
        dst_name = ID_NA
        dst_type = ID_NA
        max_sane_write_count = ID_NA
        problems = []

        # extract memcpy() arguments dst, src and n
        arg1, arg2, arg3 = args # carg_t

        # process arg3:
        # check whether third argument of memcpy is a fixed number
        # and get its value
        if arg3.op == idaapi.cot_num:
            # alternative: var_n = arg3.n.value(arg3.type)
            n_value = arg3.numval()

        # process arg2:
        # do not handle for now

        # process arg1:
        # check whether first argument (dst) is a reference to a
        # stack variable

        # does the "op" member of arg1 indicate a reference?
        if arg1.op == idaapi.cot_ref: # cexpr_t
            # if it does, get the referenced expression's "x"
            # member, which is also a cexpr_t
            ref = arg1.x # cexpr_t

            # then check whether referenced expression is a variable
            if ref.op == idaapi.cot_var: # cexpr_t
                        
                # if this is the case, get the variable's name
                # and see whether it is a stack variable.

                # v is a member of the cexpr_t class that becomes
                # valid for cot_var types. its type is "var_ref_t",
                # which has an index member. This "idx" member can be
                # used to access lvar_t members of the the lvars_t class
                # which is returned by calling get_lvars()
                lvars_idx = ref.v.idx # get index
                lvars = self.cfunc.get_lvars() # lvars_t

                # get the var_t instance of the referenced variable
                # which is our memcpy() call's "dst" variable
                var_dst = lvars[lvars_idx] # var_t
                dst_name = var_dst.name

                # check whether "dst" is on a stack frame by calling
                # is_stk_var()
                if var_dst.is_stk_var():
                    # get its offset (on a sidenote, the decompiler's
                    # stack var offsets are different to that of IDA's.
                    # They can be converted using stkoff_vd2ida() and
                    # stkoff_ida2vd(), respectively
                    offs = var_dst.get_stkoff()
                    dst_type = "stack+0x%x" % offs

                    # compute stack size and the max value for
                    # the memcpy() call's "n" function argument.
                    # refer to hexrays.hpp for explanations
                    frsize = idc.get_frame_lvar_size(e.ea)
                    frregs = idc.get_frame_regs_size(e.ea)
                    if offs <= frsize + frregs:
                        max_sane_write_count = frsize + frregs - offs
                    else:
                        problems.append("argptr")
                    
                    
                    # anything values for n > max_sane_write_count indicates
                    # code that may corrupt the stack.
                    #
                    #     n.b.: there exist further values for "n" that may be
                    #     causing problems but that'd mean we'd have to figure
                    #     out the size of all individual local variables, which is
                    #     beyond this script's scope.
                    # 
                    # so the following situation will cause this script to log a
                    # confirmed memory corruption:
                    # -> whenever the sum of a current "dst" stack variable's
                    # offset and the number "n" of bytes to be written by a memcpy()
                    # call is bigger than the current stack frame's size.
                    # Shouldn't realistically be the case in this context
                    # but once you are gonna extended this code with data flow
                    # analysis by tracking var assignments it starts to make sense ;)
                    # 
                    if type(n_value) != str and type(max_sane_write_count) != str:
                        if n_value > max_sane_write_count:
                            problems.append("memcorr")

        # get function name with its color tags removed
        name = idaapi.tag_remove(e.x.print1(None))

        self._add_func_call(MemcpyLocation(e.ea, # address of call
                            name, # name of function
                            dst_name, # name of var "dst"
                            ID_NA, # var "src"
                            n_value, # name/val of var "n"
                            dst_type, # dst type
                            max_sane_write_count, # max number of writable
                            problems)) # overflow?
        return True

    def _add_func_call(self, func_info):
        self.data.append(func_info)
        return

# -----------------------------------------------------------------------------
def is_min_sdk_ver(min_ver_required):
    return idaapi.IDA_SDK_VERSION >= min_ver_required

# -----------------------------------------------------------------------------
def get_callers(name):
    for xr in idautils.CodeRefsTo(idaapi.get_name_ea(idaapi.BADADDR, name), True):
        fn = idaapi.get_func(xr)
        if fn:
            yield fn.start_ea

# -----------------------------------------------------------------------------
def run_script():
    if not idaapi.init_hexrays_plugin():
        idaapi.msg("This script requires the HexRays decompiler plugin.")
    else:
        func_list = []
        for name in MEMCPY_FAM:
            func_list += get_callers(name)

        func_list = set(func_list)
        nfuncs = len(func_list)
        idaapi.msg("Checking %d functions." % (nfuncs))

        lv = MrsPickyListView("MrsPicky")
        lv.Show()
        
        if is_min_sdk_ver(7.3):
            aborted = False
            i = 0
            x = nfuncs / 10 if nfuncs >= 10 else nfuncs

            idaapi.show_wait_box("Working...")

            for ea in func_list:
                bars = (int(round(i/(x), 0)))
                funcname = idaapi.get_func_name(ea)
                funcname = funcname if len(funcname) < 20 else funcname[:20] + "..."
                progress = "[%s%s] : %3.2f%%" % (bars*'#', (10-bars)*'=',
                    (float(i)/float(nfuncs))*100.0)

                idaapi.replace_wait_box("Total progress: %s\n\nScanning: %s\n\n" % (
                    progress, funcname))

                try:
                    cfunc = idaapi.decompile(ea, flags = idaapi.DECOMP_NO_WAIT)
                except idaapi.DecompilationFailure:
                    idaapi.msg("Error decompiling function @ 0x%x" % ea)
                    cfunc = None

                if cfunc:
                    fp = func_parser_t(cfunc)
                    fp.apply_to(cfunc.body, None)
                    lv.feed(fp.data)

                if idaapi.user_cancelled():
                    aborted = True
                    break

                i += 1
            idaapi.hide_wait_box()
            if aborted:
                idaapi.warning("Aborted.")

        # IDA <= 7.2
        else:
            for ea in func_list:
                try:
                    cfunc = idaapi.decompile(ea)
                except idaapi.DecompilationFailure:
                    idaapi.msg("Error decompiling function @ 0x%x" % ea)
                    cfunc = None

                if cfunc:
                    fp = func_parser_t(cfunc)
                    fp.apply_to(cfunc.body, None)
                    lv.feed(fp.data)

        idaapi.msg("Done.")
run_script()
