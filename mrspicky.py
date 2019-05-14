import idaapi
import idautils

"""MrsPicky - A simple IDAPython decompiler script to scan for calls to memcpy().

This script is an example that shows how the HexRays decompiler can be
scripted in order to find, decompile and filter memcpy() functions calls.

The results are shown as a list that can be sorted and filtered using the IDA UI.
Double clicking an entry will jump to the respective call in the current
IDA or Decompiler view.

Feel free to adjust the script to suit your personal preferences ;)"""

__author__ = "Dennis Elser"

MEMCPY_FAM = ["memcpy", "memmove"]

ID_NA = "n/a"

class MemcpyFunction():
    def __init__(self, ea, name, dst, src, n, dst_on_stack):
        self.ea = ea
        self.name = name
        self.dst = dst
        self.src = src
        self.n = n
        self.dst_stack = dst_on_stack

class MrsPicky(Choose2):

    def __init__(self, title, nb = 5, flags=0, width=None, height=None, embedded=False, modal=False):
        Choose2.__init__(
            self,
            title,
            [ ["address", 8], ["name", 8], ["dst", 4], ["src", 4], ["n", 4], ["dst on stack?", 4] ],
            flags = flags,
            width = width,
            height = height,
            embedded = embedded)
        self.ea_list = []
        self.items = []

    def OnClose(self):
        self.items = []

    def OnSelectLine(self, n):
        jumpto(self.ea_list[n])

    def OnGetLine(self, n):
        return self.items[n]

    def OnGetSize(self):
        n = len(self.items)
        return n

    def feed(self, data):
        for item in data:
            self.items.append(["0x%x" % item.ea,
                            item.name,
                            item.dst,
                            item.src,
                            item.n,
                            "yes" if item.dst_stack else ID_NA])
            self.ea_list.append(item.ea)
        self.Refresh()
        return

class memcpy_scanner_t(idaapi.ctree_visitor_t):
    def __init__(self, cfunc):
        idaapi.ctree_visitor_t.__init__(self, idaapi.CV_FAST)
        self.cfunc = cfunc
        self.data = []
        return

    def _add_func_call(self, func_info):
        self.data.append(func_info)
        return

    def _scan_memcpy(self, e):
        # get memcpy func args
        args = e.a # carglist_t

        # check number of args
        if args.size() != 3: # len(args) works as well
            return False

        """ extract memcpy() arguments
        dst, src and n """
        arg1, arg2, arg3 = args # carg_t

        n_fixed = False
        n_value = ID_NA

        dst_name = ID_NA
        dst_on_stack = False

        # check whether first argument (dst) is a reference
        if arg1.op == idaapi.cot_ref: # cexpr_t
            # if it is, get referenced expression "x"
            ref = arg1.x # cexpr_t

            # then check whether referenced expression is a variable
            if ref.op == idaapi.cot_var: # cexpr_t
                        

                """if that is the case, get the variable's name
                and see whether it is a stack variable.
                v is a member of the cexpr_t class that becomes
                valid for cot_var types. its type is "var_ref_t",
                which has an index member. This "idx" member can be
                used to access lvar_t members of the the lvars_t class.
                returned by get_lvars()"""
                lvars_idx = ref.v.idx # index
                lvars = self.cfunc.get_lvars() # lvars_t

                """get the var_t instance of the referenced variable
                which is our memcpy() call's "dst" variable"""
                var_dst = lvars[lvars_idx] # var_t

                """check whether "dst" is on the stack by calling
                is_stk_var()"""
                dst_on_stack = var_dst.is_stk_var()
                dst_name = var_dst.name

        # check whether third argument of memcpy is a fixed number
        if arg3.op == idaapi.cot_num:
            n_fixed = True
            # alternative: var_n = arg3.n.value(arg3.type)
            n_value = arg3.numval()

        name = idaapi.tag_remove(e.x.print1(None))

        self._add_func_call(MemcpyFunction(e.ea, # address of call
                            name, # name of function
                            dst_name, # name of dst var
                            ID_NA, # src var
                            "0x%x" % n_value if n_fixed else n_value, # name/val of n var
                            dst_on_stack)) # dst on stack?
        return True


    def visit_expr(self, e):
        op = e.op
        if op == idaapi.cot_call:
            name = idaapi.tag_remove(e.x.print1(None))
            if name in MEMCPY_FAM:
                self._scan_memcpy(e)
        return 0  

def get_callers(name):
    for xr in idautils.CodeRefsTo(idaapi.get_name_ea(idaapi.BADADDR, name), True):
        fn = idaapi.get_func(xr)
        if fn:
            yield fn.startEA

if not idaapi.init_hexrays_plugin():
    print "This script requires the HexRays decompiler plugin."
else:
    func_list = []
    for name in MEMCPY_FAM:
        func_list += get_callers(name) 

    func_list = set(func_list)
    print "Checking %d functions." % (len(func_list))

    choser = MrsPicky("MrsPicky")
    choser.Show()
    for ea in func_list:
        try:
            cfunc = idaapi.decompile(ea)
        except idaapi.DecompilationFailure:
            print "Error decompiling function @ 0x%x" % ea
            cfunc = None
        if cfunc:
            ms = memcpy_scanner_t(cfunc)
            ms.apply_to(cfunc.body, None)
            choser.feed(ms.data)
    print "Done."