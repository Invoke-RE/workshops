#
#
# This script can be used to demangle given functions
# ported from Bindiff or other sources.

for func in bv.functions:
    # We can identify mangled function names with
    # question marks.
    if "?" in func.name:
        # Once identified we can demangle the
        # function name with the built-in demangle_ms
        dmf = demangle_ms(bv.arch, func.name)
        if(type(dmf[1]) == str):
            continue
        # The first tuple entry is the demangled function type
        ftype = dmf[0]
        # The second tuple is the function name seperated by
        # namespaces.
        fname = "::".join(dmf[1])
        # Once recovered, we can rename the function and apply the
        # demangled function type
        try:
            print(f"Renaming {func.name} to {fname}")
            func.type = ftype
            print(f"Re-typing function to {ftype}")
            func.name = fname
        except Exception as e:
            print(f"An exception occurred when renaming/retyping {func.name}: {e}")
