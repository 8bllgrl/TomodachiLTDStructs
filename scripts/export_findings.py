"""
export_findings.py (Fully Streamed & Memory-Safe)
-------------------------------------------------
Ghidra script that manually formats and streams functions and structs 
to disk line-by-line, avoiding all heavy json.dumps calls that trigger JVM OOM.
"""

import json
from java.io import BufferedWriter, FileOutputStream, OutputStreamWriter, File
from ghidra.program.model.data import Structure

DEFAULT_NAME_PREFIXES = ("FUN_", "DAT_", "PTR_", "LAB_", "SUB_", "UNK_", "switchD_", "thunk_FUN_", "thunk_fun")
MAX_SIG_BYTES = 64          
MAX_SIG_INSTRUCTIONS = 24   

def is_user_named(name):
    return not any(name.startswith(p) for p in DEFAULT_NAME_PREFIXES)

def build_signature(func):
    listing = currentProgram.getListing()
    addr = func.getEntryPoint()

    out_bytes = bytearray()
    out_mask = bytearray()

    instr = listing.getInstructionAt(addr)
    count = 0
    while instr is not None and len(out_bytes) < MAX_SIG_BYTES and count < MAX_SIG_INSTRUCTIONS:
        raw = instr.getBytes()
        mask = [1] * len(raw)

        has_ref_operand = False
        for i in range(instr.getNumOperands()):
            refs = instr.getOperandReferences(i)
            if refs and len(refs) > 0:
                has_ref_operand = True

        if has_ref_operand and len(raw) >= 4:
            for k in range(len(raw) - 4, len(raw)):
                mask[k] = 0

        out_bytes.extend(bytearray(raw))
        out_mask.extend(mask)

        count += 1
        nxt = instr.getNext()
        if nxt is None or nxt.getMinAddress().subtract(func.getEntryPoint()) > MAX_SIG_BYTES:
            break
        instr = nxt

    tokens = []
    for b, m in zip(out_bytes, out_mask):
        tokens.append("%02X" % (b & 0xFF) if m else "??")
    return " ".join(tokens)

def write_functions(writer):
    writer.write('  "functions": {\n')
    fm = currentProgram.getFunctionManager()
    base = currentProgram.getImageBase().getOffset()
    
    first = True
    count = 0
    
    for func in fm.getFunctions(True):
        name = func.getName()
        if not is_user_named(name):
            continue

        sig = build_signature(func)
        if sig.count("??") == sig.count(" ") + 1:
            continue

        entry = {
            "address_offset": "0x%x" % (func.getEntryPoint().getOffset() - base),
            "signature": sig,
            "return_type": str(func.getReturnType()),
            "calling_convention": str(func.getCallingConventionName()),
            "params": [
                {"name": p.getName(), "type": str(p.getDataType())}
                for p in func.getParameters()
            ],
        }
        comment = func.getComment()
        if comment:
            entry["comment"] = comment

        if not first:
            writer.write(',\n')
        
        writer.write('    ' + json.dumps(name) + ': ' + json.dumps(entry, sort_keys=False))
        first = False
        count += 1

    writer.write('\n  },\n')
    return count

def write_data_types(writer):
    writer.write('  "structs": {\n')
    dtm = currentProgram.getDataTypeManager()
    it = dtm.getAllDataTypes()
    
    first = True
    count = 0
    
    while it.hasNext():
        dt = it.next()
        src = dt.getSourceArchive()
        if src is not None and src.getName() == "built in":
            continue
            
        if isinstance(dt, Structure):
            if not first:
                writer.write(',\n')
            
            # Stream structure metadata header
            writer.write('    ' + json.dumps(dt.getPathName()) + ': {\n')
            writer.write('      "size": %d,\n' % dt.getLength())
            writer.write('      "fields": [\n')
            
            comp_first = True
            for comp in dt.getComponents():
                if comp is None:
                    continue
                
                f_name = comp.getFieldName() or ("field_0x%x" % comp.getOffset())
                f_type = str(comp.getDataType())
                
                if not comp_first:
                    writer.write(',\n')
                
                # Write each field object directly without large list aggregation
                writer.write('        {"offset": %d, "name": %s, "type": %s, "length": %d}' % (
                    comp.getOffset(),
                    json.dumps(f_name),
                    json.dumps(f_type),
                    comp.getLength()
                ))
                comp_first = False
            
            writer.write('\n      ]\n    }')
            first = False
            count += 1

    writer.write('\n  }\n')
    return count

def main():
    out_dir = askDirectory("Select output directory for findings.json", "Choose")
    if not out_dir:
        print("Export cancelled.")
        return

    out_file = File(out_dir.getAbsolutePath(), "findings.json")
    print("Streaming output to: " + out_file.getAbsolutePath())

    # FileOutputStream overwrites the file automatically if it already exists
    fos = FileOutputStream(out_file)
    writer = BufferedWriter(OutputStreamWriter(fos, "UTF-8"))

    try:
        writer.write('{\n')
        writer.write('  "schema_version": 1,\n')
        writer.write('  "program_name": ' + json.dumps(currentProgram.getName()) + ',\n')
        writer.write('  "language_id": ' + json.dumps(str(currentProgram.getLanguageID())) + ',\n')

        print("Streaming functions...")
        func_count = write_functions(writer)
        
        print("Streaming data types...")
        struct_count = write_data_types(writer)

        writer.write('}\n')
        print("Exported %d functions and %d structs successfully!" % (func_count, struct_count))

    finally:
        writer.close()

main()