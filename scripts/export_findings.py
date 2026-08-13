"""
export_compact_data_yml.py
-------------------------------------------------
Ghidra script that streams globals and functions into a compact YAML 
structure matching the ffxivclientstructs format, excluding signatures and classes.
"""

from java.io import BufferedWriter, FileOutputStream, OutputStreamWriter, File

DEFAULT_NAME_PREFIXES = ("FUN_", "DAT_", "PTR_", "LAB_", "SUB_", "UNK_", "switchD_", "thunk_FUN_", "thunk_fun")

def is_user_named(name):
    return not any(name.startswith(p) for p in DEFAULT_NAME_PREFIXES)

def write_globals(writer):
    writer.write('globals:\n')
    symbol_table = currentProgram.getSymbolTable()
    symbols = symbol_table.getAllSymbols(True)
    
    count = 0
    for sym in symbols:
        name = sym.getName()
        if not is_user_named(name):
            continue
        if sym.getSymbolType().toString() in ["Label", "Function"]:
            continue
            
        addr = sym.getAddress()
        writer.write('  0x%x: %s\n' % (addr.getOffset(), name))
        count += 1
    return count

def write_functions(writer):
    writer.write('functions:\n')
    fm = currentProgram.getFunctionManager()
    base = currentProgram.getImageBase().getOffset()
    
    count = 0
    for func in fm.getFunctions(True):
        name = func.getName()
        if not is_user_named(name):
            continue

        offset = func.getEntryPoint().getOffset() - base
        writer.write('  0x%x: %s\n' % (offset, name))
        count += 1
    return count

def main():
    out_dir = askDirectory("Select output directory for data.yml", "Choose")
    if not out_dir:
        print("Export cancelled.")
        return

    out_file = File(out_dir.getAbsolutePath(), "data.yml")
    print("Streaming compact YAML (globals and funcs only) to: " + out_file.getAbsolutePath())

    fos = FileOutputStream(out_file)
    writer = BufferedWriter(OutputStreamWriter(fos, "UTF-8"))

    try:
        writer.write('version: "2026.08.05.0000.0000"\n\n')
        
        print("Streaming globals...")
        write_globals(writer)
        writer.write('\n')
        
        print("Streaming functions...")
        write_functions(writer)

        print("Successfully exported compact data.yml without signatures!")

    finally:
        writer.close()

main()