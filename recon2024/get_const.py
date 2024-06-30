def is_const(inst: HighLevelILInstruction) -> int:
    if isinstance(inst, HighLevelILConst):
        return inst.value.value
    
a = list(bv.hlil_instructions)[0]

print(list(a.traverse(is_const)))