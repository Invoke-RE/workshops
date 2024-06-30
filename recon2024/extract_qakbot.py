import pefile

def extract_key_resource_id(func: binaryninja.function.Function) -> tuple[bytes, int]:
    finstr = None
    key = None
    rsrc_id = None
    
    for instr in func.hlil.instructions:
        for token in instr.tokens:
            if '__builtin_strncpy' == token.text:
                finstr = instr
        if finstr:
            break
    
    if finstr:
        # Access second operand of __builtin_strncpy
        key_param = finstr.params[1]
        # Access constant data from parameter
        key = bytes(key_param.constant_data.data)
    
    rsrc_instr = list(func.hlil.instructions)[finstr.instr_index+1]
    rsrc_id = rsrc_instr.operands[1].value.value

    return key, rsrc_id

def carve_pe(data: bytes) -> list:
    from refinery import carve_pe
    # This syntax is specific to Binary Refinery's
    # operator overloading and is valid Python.
    carved = data | carve_pe | []
    return carved

def xor(key: bytes, ct: bytes) -> bytes:
    r = bytes()
    for i, b in enumerate(ct):
        r += (b ^ key[i % len(key)]).to_bytes(1, 'little')
    return r

def extract_resource(fpath: str, rsrcid: int) -> bytes:
    rsrc_data = None
    pe = pefile.PE(fpath)
    pe_mapped = pe.get_memory_mapped_image()
    for rsrc in pe.DIRECTORY_ENTRY_RESOURCE.entries:
        for entry in rsrc.directory.entries:
            if entry.struct.Name == rsrcid:
                rsrc_offset = entry.directory.entries[0].data.struct.OffsetToData
                rsrc_size = entry.directory.entries[0].data.struct.Size
                rsrc_data = pe_mapped[rsrc_offset:rsrc_offset + rsrc_size]
    return rsrc_data

addr = 0x691bc000
func = bv.get_function_at(addr)
# This assumes the bndb is the same filename as the sample file
# and are within the same directory. 
path = re.sub(r"\.bndb", "", func.view.file.filename)

# Extract XOR key and resource ID
key, rsrc_id = extract_key_resource_id(func)
print(F"Key: {key} // Resource ID: {rsrc_id}")

# Exract embedded resource using resource ID and
# decrypt it
rsrc_data = extract_resource(path, rsrc_id)
pt = xor(key, rsrc_data)

# Carve embedded PEs from shellcode and first
# stage PE
first_pe = carve_pe(pt)[0]
second_pe = carve_pe(first_pe)[0]

# Write Qakbot payload to disk
fw = open(F"{path}_qakbot.bin", "wb")
fw.write(second_pe)
fw.close()