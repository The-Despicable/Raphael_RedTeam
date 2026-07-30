"""
Chrome Extension Forensics Chain — Raphael Techniques
Three atomic nodes: js_deobfuscate, leveldb_parse, xor_crack
Chain is resolved by Planner via prerequisite graph.
"""
import re
from raphael.models.target_model import ConstraintDelta


def js_deobfuscate_parse(stdout: str, target: str) -> ConstraintDelta:
    """Parse deobfuscated JS output for evidence of decoded logic."""
    affordances = set()
    stdout_lower = stdout.lower()
    # Check for indicators of successful deobfuscation
    if "http" in stdout_lower or "function" in stdout_lower:
        affordances.add("JS_DEOBFUSCATED")
    if "xhr" in stdout_lower or "xmlhttp" in stdout_lower:
        affordances.add("js_xhr_detected")
    if "chrome" in stdout_lower or "browser" in stdout_lower:
        affordances.add("js_extension_api_detected")
    if "eval" in stdout_lower:
        affordances.add("js_eval_remnant")
    if "decode" in stdout_lower or "decrypt" in stdout_lower:
        affordances.add("js_crypto_logic_detected")
    # If nothing recognizable, flag as still obfuscated
    if not affordances:
        affordances.add("js_still_obfuscated")
    return ConstraintDelta(
        new_affordances=affordances,
        new_constraints={"deobfuscated_output": stdout[:5000]},
        resolved_unknowns={"js_obfuscation_unknown"},
        evidence=stdout[:2000],
    )


def leveldb_data_parse(stdout: str, target: str) -> ConstraintDelta:
    """Parse LevelDB hex dump output for encrypted payloads."""
    affordances = set()
    constraints = {}
    lines = [l for l in stdout.splitlines() if l.strip()]
    if not lines:
        affordances.add("leveldb_empty")
        return ConstraintDelta(
            new_affordances=affordances,
            resolved_unknowns={"leveldb_data_unknown"},
            evidence=stdout[:1000],
        )
    affordances.add("LEVELDB_RECORDS_EXTRACTED")
    affordances.add(f"leveldb_record_count:{len(lines)}")
    # Check for HTB{ pattern in hex-decoded content
    for line in lines:
        if ":" in line:
            hex_data = line.split(":", 1)[1]
            try:
                raw = bytes.fromhex(hex_data)
                if b"HTB{" in raw:
                    affordances.add("flag_encrypted_detected")
                    # Find offset for XOR key derivation
                    idx = raw.index(b"HTB{")
                    constraints["flag_offset"] = str(idx)
            except (ValueError, AttributeError):
                pass
    return ConstraintDelta(
        new_affordances=affordances,
        new_constraints=constraints,
        resolved_unknowns={"leveldb_data_unknown"},
        evidence=stdout[:2000],
    )


def xor_crack_parse(stdout: str, target: str) -> ConstraintDelta:
    """Parse XOR sweep output for decrypted flags."""
    affordances = set()
    constraints = {}
    match = re.search(r'HTB\{[^}]{3,80}\}', stdout)
    if match:
        affordances.add("FLAG_DECRYPTED")
        constraints["flag"] = match.group(0)
        affordances.add("flag_captured")
    elif "flag" in stdout.lower() and "not" in stdout.lower():
        affordances.add("xor_sweep_no_flag")
    else:
        affordances.add("xor_sweep_incomplete")
    return ConstraintDelta(
        new_affordances=affordances,
        new_constraints=constraints,
        resolved_unknowns={"xor_decrypt_unknown"},
        evidence=stdout[:2000],
    )
