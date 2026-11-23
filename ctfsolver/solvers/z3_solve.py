"""Automated Z3 symbolic constraint solver for crackmes and equation systems."""
from __future__ import annotations

import re
from typing import Any

from ..flags import scan_text


def parse_and_solve(equations: list[str] | str, flag_format: str = "", length_hint: int = 0) -> dict[str, Any]:
    """Parse linear / bitwise equation strings and solve using Z3 BitVec / Int logic."""
    try:
        import z3
    except ImportError:
        return {"solved": False, "flag": "", "output": "z3-solver is not installed in the python environment."}

    if isinstance(equations, str):
        lines = [line.strip() for line in equations.replace(";", "\n").splitlines() if line.strip()]
    else:
        lines = [line.strip() for line in equations if line.strip()]

    if not lines:
        return {"solved": False, "flag": "", "output": "No equations provided."}

    # Normalize equations: convert `==` or `=`
    norm_eqs = []
    for line in lines:
        # Strip C-style 'if (' ... ')'
        line = re.sub(r"^\s*if\s*\((.*)\)\s*$", r"\1", line)
        line = re.sub(r"^\s*assert\s*\((.*)\)\s*$", r"\1", line)
        if "==" in line:
            norm_eqs.append(line)
        elif "=" in line and not any(op in line for op in ["<=", ">=", "!="]):
            norm_eqs.append(line.replace("=", "=="))
        else:
            norm_eqs.append(line)

    # Find all indexed variables: flag[0], c[1], x[2], v0, x0, etc.
    # Pattern 1: name[number]
    var_indices: set[int] = set()
    for eq in norm_eqs:
        for match in re.finditer(r"(?:flag|input|buf|str|s|c|arr|v|x|data)\[(\d+)\]", eq, re.IGNORECASE):
            var_indices.add(int(match.group(1)))
        for match in re.finditer(r"\b(?:c|v|x|chr|flag|b)_?(\d+)\b", eq, re.IGNORECASE):
            var_indices.add(int(match.group(1)))

    if not var_indices:
        return {"solved": False, "flag": "", "output": "Could not identify indexed flag variables (e.g. flag[i], c[i], x0)."}

    max_idx = max(var_indices)
    var_count = max_idx + 1

    # Create Z3 8-bit BitVec variables for each character
    s = z3.Solver()
    vars_dict: dict[str, z3.BitVecRef] = {}
    var_list: list[z3.BitVecRef] = []

    for i in range(var_count):
        v = z3.BitVec(f"c_{i}", 8)
        var_list.append(v)
        # Aliases for python eval
        vars_dict[f"c_{i}"] = v
        vars_dict[f"c{i}"] = v
        vars_dict[f"v{i}"] = v
        vars_dict[f"x{i}"] = v

        # Printable ASCII bounds for flag characters: 32 <= c <= 126
        s.add(z3.UGE(v, 32))
        s.add(z3.ULE(v, 126))

    # Construct safe namespace for eval
    safe_globals = {
        "__builtins__": None,
        "BitVec": z3.BitVec,
        "BitVecVal": z3.BitVecVal,
    }

    # Custom wrapper class for indexing e.g. flag[i]
    class VarListAccessor:
        def __getitem__(self, idx: int) -> z3.BitVecRef:
            if idx < len(var_list):
                return var_list[idx]
            # Auto-expand if needed
            while len(var_list) <= idx:
                new_v = z3.BitVec(f"c_{len(var_list)}", 8)
                var_list.append(new_v)
                s.add(z3.UGE(new_v, 32))
                s.add(z3.ULE(new_v, 126))
            return var_list[idx]

    accessor = VarListAccessor()
    safe_locals: dict[str, Any] = {
        "flag": accessor,
        "input": accessor,
        "buf": accessor,
        "str": accessor,
        "c": accessor,
        "arr": accessor,
        "v": accessor,
        "x": accessor,
        "data": accessor,
    }
    safe_locals.update(vars_dict)

    added_constraints = 0
    parse_errors = []

    for eq in norm_eqs:
        # Convert hex literals in equation: e.g. 0x42
        # Translate single == into python comparison
        try:
            # Substitute bare c0, x0 into c[0], x[0] if needed
            trans_eq = re.sub(r"\b([cvx])(\d+)\b", r"\1[\2]", eq)
            expr = eval(trans_eq, safe_globals, safe_locals)
            s.add(expr)
            added_constraints += 1
        except Exception as e:
            parse_errors.append(f"{eq} -> {e}")

    if added_constraints == 0:
        return {
            "solved": False,
            "flag": "",
            "output": f"Failed to parse equations. Errors:\n" + "\n".join(parse_errors[:5]),
        }

    # Check satisfiability
    check_res = s.check()
    if check_res != z3.sat:
        return {
            "solved": False,
            "flag": "",
            "output": f"Z3 check result: {check_res} (equations unsatisfiable with ASCII constraints)",
        }

    m = s.model()
    recovered_chars = []
    for i in range(len(var_list)):
        val_ref = m.eval(var_list[i])
        try:
            val_int = val_ref.as_long()
            recovered_chars.append(chr(val_int))
        except Exception:
            recovered_chars.append("?")

    candidate = "".join(recovered_chars)
    flags = scan_text(candidate)

    # If not already flag-wrapped and flag_format is provided
    formatted_flag = candidate
    if flags:
        formatted_flag = flags[0]["flag"]
    elif "{" not in candidate and "}" not in candidate:
        formatted_flag = f"flag{{{candidate}}}"
        flags = scan_text(formatted_flag)

    return {
        "solved": True,
        "flag": formatted_flag,
        "raw": candidate,
        "flags": flags,
        "constraints_count": added_constraints,
        "output": f"Z3 successfully recovered {len(recovered_chars)} chars: {formatted_flag}",
    }


def scan_and_solve(text: str) -> dict[str, Any]:
    """Scan code or briefing text for constraint equation blocks and solve."""
    # Look for clusters of equations
    eq_pattern = re.compile(
        r"(?:(?:flag|input|buf|str|c|v|x)\[\d+\]|[cvx]\d+)\s*(?:[\^+\-*&|]\s*[^=]+)?\s*==\s*(?:0x[0-9a-fA-F]+|\d+)",
        re.IGNORECASE,
    )
    matches = eq_pattern.findall(text)
    if len(matches) >= 3:
        return parse_and_solve(matches)
    return {"solved": False, "flag": "", "output": "No equation block detected."}
