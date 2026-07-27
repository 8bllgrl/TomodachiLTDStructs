"""
import_findings.py
-------------------
Ghidra script (run via Script Manager) that reads a findings.json file
(produced by export_findings.py, e.g. one you pulled down from a GitHub
repo) and applies it to the program YOU currently have open in YOUR OWN
Ghidra project.

For each function entry, this script:
  1. Parses the wildcarded byte signature into a (pattern, mask) pair
  2. Searches your program's memory for that pattern
  3. If exactly one match is found, checks whether YOU have already put
     your own work into that function locally
  4. If zero or multiple matches are found, it SKIPS that entry and logs
     it -- ambiguous or missing matches are never guessed at

MERGE SAFETY (multi-contributor branches)
------------------------------------------
This script is written for the situation where several people are
independently reverse-engineering different parts of the same binary and
periodically syncing via a shared findings.json, possibly via separate
git branches. To avoid one person's import stomping on another person's
in-progress local work, a function/comment is only overwritten if it is
still in an "untouched" state locally:

  - Function NAME is only applied if the local function still has an
    auto-generated Ghidra name (FUN_/SUB_/etc) OR already matches the
    incoming name exactly. If you've already given it a *different*
    name locally, the import leaves your name alone and logs a
    [CONFLICT] instead.
  - Function COMMENT is only applied if the local function currently has
    no comment. If you already wrote your own comment, it's left alone.

By default the script will NOT overwrite anything you've already named
or annotated -- see the prompt at the start of main() to opt into force
mode if you explicitly want to overwrite local work with the incoming
file (e.g. reconciling after you know your local names were wrong).

This script never modifies or reads anyone else's .gpr file, and it does
not require or fetch a binary from anywhere -- it only operates on
whatever program you already imported into Ghidra yourself.

No external dependencies -- uses only Python's built-in json module, so
this works under both Jython and PyGhidra with no pip install needed.
"""

import json
from ghidra.program.model.symbol import SourceType
from ghidra.util.task import ConsoleTaskMonitor
from ghidra.program.model.data import (
    StructureDataType, CategoryPath, PointerDataType, ArrayDataType,
    CharDataType, ByteDataType, SignedByteDataType,
    ShortDataType, UnsignedShortDataType,
    IntegerDataType, UnsignedIntegerDataType,
    LongDataType, UnsignedLongDataType,
    LongLongDataType, UnsignedLongLongDataType,
    FloatDataType, DoubleDataType, BooleanDataType, VoidDataType,
    Undefined1DataType, Undefined2DataType, Undefined4DataType, Undefined8DataType,
    DataType,
)

DEFAULT_NAME_PREFIXES = ("FUN_", "DAT_", "PTR_", "LAB_", "SUB_", "UNK_", "switchD_", "thunk_FUN_", "thunk_fun")


def is_user_named(name):
    """True if this looks like a name a human gave it, not an auto label."""
    return not any(name.startswith(p) for p in DEFAULT_NAME_PREFIXES)


def parse_signature(sig):
    tokens = sig.split()
    pattern = bytearray()
    mask = bytearray()
    for t in tokens:
        if t == "??":
            pattern.append(0)
            mask.append(0)
        else:
            pattern.append(int(t, 16))
            mask.append(0xFF)
    return bytes(pattern), bytes(mask)


def find_signature_matches(pattern, mask, stop_after=2):
    """Return up to `stop_after` matches; stop early once ambiguous."""
    mem = currentProgram.getMemory()
    monitor = ConsoleTaskMonitor()
    matches = []
    addr = mem.getMinAddress()
    while addr is not None and len(matches) < stop_after:
        found = mem.findBytes(addr, pattern, mask, True, monitor)
        if found is None:
            break
        matches.append(found)
        try:
            addr = found.add(1)
        except Exception:
            break
    return matches


DEFAULT_FIELD_NAME_RE_PREFIX = "field_0x"

BUILTIN_TYPE_MAP = {
    "char": CharDataType.dataType,
    "byte": ByteDataType.dataType,
    "sbyte": SignedByteDataType.dataType,
    "short": ShortDataType.dataType,
    "ushort": UnsignedShortDataType.dataType,
    "int": IntegerDataType.dataType,
    "uint": UnsignedIntegerDataType.dataType,
    "long": LongDataType.dataType,
    "ulong": UnsignedLongDataType.dataType,
    "longlong": LongLongDataType.dataType,
    "ulonglong": UnsignedLongLongDataType.dataType,
    "float": FloatDataType.dataType,
    "double": DoubleDataType.dataType,
    "bool": BooleanDataType.dataType,
    "void": VoidDataType.dataType,
    "undefined1": Undefined1DataType.dataType,
    "undefined2": Undefined2DataType.dataType,
    "undefined4": Undefined4DataType.dataType,
    "undefined8": Undefined8DataType.dataType,
}


def is_default_field_name(name):
    return name is None or name.startswith(DEFAULT_FIELD_NAME_RE_PREFIX)


def lookup_named_type(dtm, name, local_structs):
    """Look up a type by bare name: local structs created this import first,
    then built-ins, then anything already in the program's data type
    manager (covers types the user already has from elsewhere)."""
    if name in local_structs:
        return local_structs[name]
    if name in BUILTIN_TYPE_MAP:
        return BUILTIN_TYPE_MAP[name]

    it = dtm.getAllDataTypes()
    while it.hasNext():
        dt = it.next()
        if dt.getName() == name:
            return dt
    return None


def resolve_field_type(dtm, type_str, fallback_length, local_structs):
    """
    Best-effort resolution of an exported type-name string (e.g. 'Foo *',
    'undefined4', 'char[16]') back into a real Ghidra DataType. Falls back
    to an appropriately-sized 'undefined' placeholder if the name can't be
    matched, so the struct's overall layout/size stays correct even when a
    specific field's type can't be resolved. This does not attempt to
    handle every possible type string (bitfields, function pointer
    typedefs, templated/generic names, anonymous nested structs, etc are
    out of scope here).
    """
    s = type_str.strip()

    ptr_count = 0
    while s.endswith("*"):
        ptr_count += 1
        s = s[:-1].strip()

    array_len = None
    if s.endswith("]") and "[" in s:
        base, _, rest = s.partition("[")
        num = rest.rstrip("]").strip()
        if num.isdigit():
            array_len = int(num)
            s = base.strip()

    dt = lookup_named_type(dtm, s, local_structs)

    if dt is None:
        fallback_map = {1: Undefined1DataType.dataType, 2: Undefined2DataType.dataType,
                         4: Undefined4DataType.dataType, 8: Undefined8DataType.dataType}
        dt = fallback_map.get(fallback_length, DataType.DEFAULT)

    if array_len:
        dt = ArrayDataType(dt, array_len, dt.getLength())
    for _ in range(ptr_count):
        dt = PointerDataType(dt)

    return dt


def create_struct_shells(structs):
    """
    Pass 1: create (or fetch existing) empty structs of the correct total
    size for every incoming struct, keyed by bare name, BEFORE filling in
    any fields. This lets structs that reference each other resolve
    correctly regardless of which order they're processed in.
    """
    dtm = currentProgram.getDataTypeManager()
    local_structs = {}
    for path, info in structs.items():
        parts = path.rsplit("/", 1)
        cat_path = parts[0] if len(parts) > 1 and parts[0] else "/"
        name = parts[-1]

        existing = lookup_named_type(dtm, name, {})
        if existing is not None and existing.getLength() == info["size"]:
            local_structs[name] = existing
            continue

        shell = StructureDataType(CategoryPath(cat_path), name, info["size"])
        added = dtm.addDataType(shell, None)
        local_structs[added.getName()] = added
    return local_structs


def apply_struct_fields(name, dt, info, local_structs, force):
    """Returns (applied_count, conflict_count)."""
    dtm = currentProgram.getDataTypeManager()
    applied = 0
    conflicts = 0

    for field in info["fields"]:
        offset = field["offset"]
        incoming_name = field["name"]
        length = field["length"]

        try:
            existing_comp = dt.getComponentAt(offset)
        except Exception:
            existing_comp = None

        existing_name = existing_comp.getFieldName() if existing_comp else None

        if (not force and existing_comp is not None
                and not is_default_field_name(existing_name)
                and existing_name != incoming_name):
            print("[CONFLICT] %s.%s: local field at offset 0x%x already named '%s' -- keeping local"
                  % (name, incoming_name, offset, existing_name))
            conflicts += 1
            continue

        field_type = resolve_field_type(dtm, field["type"], length, local_structs)
        try:
            dt.replaceAtOffset(offset, field_type, length, incoming_name, None)
            applied += 1
        except Exception as e:
            print("[WARN] %s.%s at offset 0x%x: could not apply (%s)" % (name, incoming_name, offset, e))

    return applied, conflicts


def apply_structs(structs, force):
    if not structs:
        return 0, 0
    local_structs = create_struct_shells(structs)

    applied_total = 0
    conflict_total = 0
    for path, info in structs.items():
        name = path.rsplit("/", 1)[-1]
        dt = local_structs.get(name)
        if dt is None:
            print("[SKIP] struct %s: could not create/find shell type" % name)
            continue
        applied, conflicts = apply_struct_fields(name, dt, info, local_structs, force)
        applied_total += applied
        conflict_total += conflicts
        print("[STRUCT] %s: %d field(s) applied, %d conflict(s)" % (name, applied, conflicts))

    return applied_total, conflict_total

def apply_function(name, entry, force):
    """
    Returns a status string: "applied", "conflict", "miss", "ambig", "skip"
    """
    sig = entry.get("signature")
    if not sig:
        print("[SKIP] %s: no signature in entry" % name)
        return "skip"

    pattern, mask = parse_signature(sig)
    matches = find_signature_matches(pattern, mask)

    if len(matches) == 0:
        print("[MISS] %s: signature not found (binary differs or function was patched out)" % name)
        return "miss"
    if len(matches) > 1:
        print("[AMBIG] %s: signature matched more than once, skipping (widen MAX_SIG_BYTES on export)" % name)
        return "ambig"

    addr = matches[0]
    fm = currentProgram.getFunctionManager()
    func = fm.getFunctionAt(addr)
    if func is None:
        func = createFunction(addr, name)
    if func is None:
        print("[SKIP] %s: could not create/find a function at %s" % (name, addr))
        return "skip"

    existing_name = func.getName()
    name_is_conflict = (
        not force
        and is_user_named(existing_name)
        and existing_name != name
    )

    conflict = False
    if name_is_conflict:
        print("[CONFLICT] %s: local function at %s is already named '%s' -- keeping your local name"
              % (name, addr, existing_name))
        conflict = True
    else:
        if existing_name != name:
            func.setName(name, SourceType.USER_DEFINED)

    existing_comment = func.getComment()
    incoming_comment = entry.get("comment")
    if incoming_comment:
        if existing_comment and not force:
            print("[CONFLICT] %s: local comment already present, not overwriting" % name)
            conflict = True
        elif not existing_comment or force:
            func.setComment(incoming_comment)

    if conflict:
        return "conflict"

    print("[OK] %s -> %s" % (name, addr))
    return "applied"


def main():
    f = askFile("Select findings.json", "Import")
    fh = open(f.getAbsolutePath())
    try:
        data = json.loads(fh.read())
    finally:
        fh.close()

    funcs = data.get("functions", {})
    print("Loaded %d function entries from %s (schema v%s, source program: %s)" % (
        len(funcs), f.getName(), data.get("schema_version", "?"), data.get("program_name", "unknown")
    ))

    force = askYesNo(
        "Overwrite local work?",
        "Force mode: OVERWRITE any function names/comments AND struct field "
        "names you've already set locally with the incoming file's values?\n\n"
        "Choose NO (recommended) to only fill in functions/fields you "
        "haven't touched yet, and skip anything you've already named or "
        "annotated yourself -- safe for multiple contributors syncing the "
        "same findings.json.\n\n"
        "Choose YES only if you specifically want this import to replace "
        "your local names/comments."
    )

    counts = {"applied": 0, "conflict": 0, "miss": 0, "ambig": 0, "skip": 0}
    conflicts = []

    tx = currentProgram.startTransaction("Import findings")
    try:
        for name, entry in funcs.items():
            status = apply_function(name, entry, force)
            counts[status] += 1
            if status == "conflict":
                conflicts.append(name)

        struct_applied, struct_conflicts = apply_structs(data.get("structs", {}), force)
    finally:
        currentProgram.endTransaction(tx, True)

    print("")
    print("-- Functions --")
    print("Applied:   %d" % counts["applied"])
    print("Conflicts: %d (your local names/comments were kept -- see list below)" % counts["conflict"])
    print("Missed:    %d (signature not found in this binary)" % counts["miss"])
    print("Ambiguous: %d (signature matched more than once)" % counts["ambig"])
    print("Skipped:   %d (no usable signature/function)" % counts["skip"])

    print("")
    print("-- Structs --")
    print("Fields applied:   %d" % struct_applied)
    print("Field conflicts:  %d (your local field names were kept)" % struct_conflicts)

    if conflicts:
        print("")
        print("Functions kept as your local version (re-run with force=YES to overwrite):")
        for n in conflicts:
            print("  - %s" % n)

    print("")
    print("Not yet handled: enums, unions, typedefs, bitfields, and anonymous")
    print("nested structs are not exported/imported by this script -- struct")
    print("field types that can't be matched fall back to an appropriately")
    print("sized 'undefined' placeholder so layout/size stay correct.")


main()