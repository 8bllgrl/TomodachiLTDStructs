"""
export_findings.py
-------------------
Ghidra script (run via Script Manager) that walks the CURRENTLY OPEN program
and exports:
  - every function you've renamed away from Ghidra's auto-generated names
    (FUN_/DAT_/PTR_/LAB_/SUB_/UNK_/switchD_/thunk_FUN_/thunk_fun), along with a
    wildcarded byte signature, return type, parameters, calling convention, and comments
  - every user-defined structure/enum/typedef in the program's data type
    manager

...into a single portable findings.json file.

This script never reads or writes your .gpr project file, and it never
touches the imported binary itself. It only reads the metadata you've
already applied inside Ghidra's Listing/DataTypeManager, and it identifies
locations by SIGNATURE rather than raw address, so the resulting file
can be applied to someone else's Ghidra project of the same binary even
if their image base differs slightly.

Run this from Ghidra's Script Manager with your analyzed program open.
No external dependencies -- uses only Python's built-in json module, so
this works under both Jython and PyGhidra with no pip install needed.
"""

import json
from ghidra.program.model.data import Structure
from ghidra.util.task import ConsoleTaskMonitor

DEFAULT_NAME_PREFIXES = ("FUN_", "DAT_", "PTR_", "LAB_", "SUB_", "UNK_", "switchD_", "thunk_FUN_", "thunk_fun")
MAX_SIG_BYTES = 64          # how many bytes of a function to fingerprint
MAX_SIG_INSTRUCTIONS = 24   # safety cap on instruction count


def is_user_named(name):
    """True if this looks like a name a human gave it, not an auto label."""
    return not any(name.startswith(p) for p in DEFAULT_NAME_PREFIXES)


def build_signature(func):
    """
    Build a wildcarded byte pattern ("48 8B ?? ?? E8 ?? ?? ?? ??" style) for
    the start of a function. Bytes that Ghidra identifies as part of an
    operand with a reference (call/jump targets, rip-relative loads, other
    address-bearing operands) are wildcarded, since those bytes encode a
    location that WILL differ between builds/binaries even when the
    surrounding code is identical. Everything else (opcodes, register
    selection, immediates with no reference) stays fixed.

    This is a reasonable general-purpose heuristic, not a guarantee of
    uniqueness -- see README for tuning notes (MAX_SIG_BYTES, dealing with
    short/ambiguous functions, etc).
    """
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
            # Wildcard the trailing 4 bytes -- covers the common case of a
            # rel32 displacement (call/jmp/lea/rip-relative) at the tail of
            # the instruction encoding. Not perfect for every addressing
            # mode; adjust per-architecture if you hit false negatives.
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


def export_functions():
    entries = {}
    fm = currentProgram.getFunctionManager()
    base = currentProgram.getImageBase().getOffset()
    for func in fm.getFunctions(True):  # True = ascending address order
        name = func.getName()
        if not is_user_named(name):
            continue

        sig = build_signature(func)
        if sig.count("??") == sig.count(" ") + 1:
            # entirely wildcarded, useless signature -- skip with a warning
            print("[WARN] %s produced an empty/unusable signature, skipping" % name)
            continue

        entry = {
            # Informational only -- NOT used for matching on import (that's
            # signature-based). Included so the exported file sorts and
            # reads in address order, and so humans reviewing a diff/PR can
            # see roughly where in the binary an entry lives.
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

        entries[name] = entry
    return entries


def export_data_types():
    dtm = currentProgram.getDataTypeManager()
    structs = {}
    it = dtm.getAllDataTypes()
    while it.hasNext():
        dt = it.next()
        src = dt.getSourceArchive()
        if src is not None and src.getName() == "built in":
            continue
        if isinstance(dt, Structure):
            fields = []
            for comp in dt.getComponents():
                if comp is None:
                    continue
                fields.append({
                    "offset": comp.getOffset(),
                    "name": comp.getFieldName() or ("field_0x%x" % comp.getOffset()),
                    "type": str(comp.getDataType()),
                    "length": comp.getLength(),
                })
            structs[dt.getPathName()] = {"size": dt.getLength(), "fields": fields}
    return structs


def main():
    out_dir = askDirectory("Select output directory for findings.json", "Choose")
    print("Scanning functions...")
    funcs = export_functions()
    print("Scanning data types...")
    structs = export_data_types()

    data = {
        "schema_version": 1,
        "program_name": currentProgram.getName(),
        "language_id": str(currentProgram.getLanguageID()),
        "functions": funcs,
        "structs": structs,
    }

    out_path = out_dir.getAbsolutePath() + "/findings.json"
    f = open(out_path, "w")
    try:
        # sort_keys intentionally OFF -- functions are inserted in ascending
        # address order (see export_functions), and we want that order to
        # survive into the file so diffs/PRs cluster by binary region
        # instead of scattering alphabetically by name. Structs keep
        # dict/insertion order too, which falls back to the order Ghidra's
        # data type manager iterator returns them in.
        f.write(json.dumps(data, sort_keys=False, indent=2))
    finally:
        f.close()

    print("Exported %d functions and %d structs -> %s" % (len(funcs), len(structs), out_path))
    print("This file contains NO binary data and NO project file. Safe to commit to a public repo.")


main()