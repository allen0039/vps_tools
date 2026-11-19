"""Zero-dependency TOML loader (Python 3.11+ tomllib with 3.9/3.10 fallback) and deterministic TOML helpers."""

from __future__ import annotations

from typing import Any, Dict, List, Tuple

try:
    import tomllib as _stdlib_tomllib
except ModuleNotFoundError:  # Python < 3.11 (e.g. macOS host Python 3.9 for client ingress checks)
    _stdlib_tomllib = None


class TomlParseError(ValueError):
    """Raised when TOML syntax is invalid."""


def _strip_comment(line: str) -> str:
    """Remove unquoted # comments while preserving # inside quotes."""
    in_double = False
    in_single = False
    escaped = False
    for idx, ch in enumerate(line):
        if escaped:
            escaped = False
            continue
        if in_double:
            if ch == "\\":
                escaped = True
            elif ch == '"':
                in_double = False
        elif in_single:
            if ch == "'":
                in_single = False
        else:
            if ch == '"':
                in_double = True
            elif ch == "'":
                in_single = True
            elif ch == "#":
                return line[:idx]
    return line


def _split_top_level(text: str, sep: str) -> List[str]:
    """Split text on sep outside quotes and nested brackets."""
    parts: List[str] = []
    cur: List[str] = []
    in_double = False
    in_single = False
    escaped = False
    bracket_depth = 0
    for ch in text:
        if escaped:
            cur.append(ch)
            escaped = False
            continue
        if in_double:
            cur.append(ch)
            if ch == "\\":
                escaped = True
            elif ch == '"':
                in_double = False
        elif in_single:
            cur.append(ch)
            if ch == "'":
                in_single = False
        else:
            if ch == '"':
                in_double = True
                cur.append(ch)
            elif ch == "'":
                in_single = True
                cur.append(ch)
            elif ch in "[{":
                bracket_depth += 1
                cur.append(ch)
            elif ch in "]}":
                bracket_depth = max(0, bracket_depth - 1)
                cur.append(ch)
            elif ch == sep and bracket_depth == 0:
                parts.append("".join(cur))
                cur = []
            else:
                cur.append(ch)
    parts.append("".join(cur))
    return parts


def _split_key_value(line: str) -> Tuple[str, str]:
    """Split a key = value line outside quotes."""
    in_double = False
    in_single = False
    escaped = False
    for idx, ch in enumerate(line):
        if escaped:
            escaped = False
            continue
        if in_double:
            if ch == "\\":
                escaped = True
            elif ch == '"':
                in_double = False
        elif in_single:
            if ch == "'":
                in_single = False
        else:
            if ch == '"':
                in_double = True
            elif ch == "'":
                in_single = True
            elif ch == "=":
                return line[:idx].strip(), line[idx + 1 :].strip()
    raise TomlParseError(f"Expected '=' in assignment: {line}")


def _parse_key_path(raw_key: str) -> List[str]:
    """Parse a dotted TOML key path."""
    parts = _split_top_level(raw_key.strip(), ".")
    keys: List[str] = []
    for part in parts:
        token = part.strip()
        if not token:
            raise TomlParseError(f"Empty key segment in {raw_key!r}")
        if (token.startswith('"') and token.endswith('"')) or (
            token.startswith("'") and token.endswith("'")
        ):
            keys.append(_parse_string(token))
        else:
            for ch in token:
                if not (ch.isalnum() or ch in "_-"):
                    raise TomlParseError(f"Invalid bare key {token!r}")
            keys.append(token)
    return keys


def _parse_string(raw: str) -> str:
    """Parse basic or literal single-line TOML string."""
    if raw.startswith("'") and raw.endswith("'") and len(raw) >= 2:
        return raw[1:-1]
    if raw.startswith('"') and raw.endswith('"') and len(raw) >= 2:
        inner = raw[1:-1]
        out: List[str] = []
        i = 0
        escapes = {
            "b": "\b",
            "t": "\t",
            "n": "\n",
            "f": "\f",
            "r": "\r",
            '"': '"',
            "\\": "\\",
        }
        while i < len(inner):
            ch = inner[i]
            if ch == "\\":
                i += 1
                if i >= len(inner):
                    raise TomlParseError(f"Unterminated escape in {raw!r}")
                esc = inner[i]
                if esc in escapes:
                    out.append(escapes[esc])
                elif esc == "u" and i + 4 < len(inner):
                    out.append(chr(int(inner[i + 1 : i + 5], 16)))
                    i += 4
                elif esc == "U" and i + 8 < len(inner):
                    out.append(chr(int(inner[i + 1 : i + 9], 16)))
                    i += 8
                else:
                    raise TomlParseError(f"Unsupported escape \\{esc} in {raw!r}")
            else:
                out.append(ch)
            i += 1
        return "".join(out)
    raise TomlParseError(f"Invalid string literal: {raw!r}")


def _parse_value(raw: str) -> Any:
    """Parse a TOML value (string, bool, int, float, array)."""
    val = raw.strip()
    if not val:
        raise TomlParseError("Empty value")
    if (val.startswith('"') and val.endswith('"')) or (
        val.startswith("'") and val.endswith("'")
    ):
        return _parse_string(val)
    if val == "true":
        return True
    if val == "false":
        return False
    if val.startswith("[") and val.endswith("]"):
        inner = val[1:-1].strip()
        if not inner:
            return []
        items = []
        for item in _split_top_level(inner, ","):
            stripped = item.strip()
            if stripped:
                items.append(_parse_value(stripped))
        return items
    clean_num = val.replace("_", "")
    if clean_num.startswith(("+", "-")) or clean_num.isdigit():
        try:
            return int(clean_num, 10)
        except ValueError:
            pass
    try:
        return float(clean_num)
    except ValueError as exc:
        raise TomlParseError(f"Unsupported TOML value: {raw!r}") from exc


def _fallback_loads(text: str) -> Dict[str, Any]:
    """Minimal strict TOML parser for Python 3.9/3.10 fallback."""
    root: Dict[str, Any] = {}
    current_table: Dict[str, Any] = root
    lines = text.splitlines()
    idx = 0

    while idx < len(lines):
        raw_line = _strip_comment(lines[idx]).strip()
        idx += 1
        if not raw_line:
            continue

        # Handle multiline arrays cleanly if '[' is opened on this line.
        while "[" in raw_line and not raw_line.startswith("["):
            _, rhs = _split_key_value(raw_line)
            if rhs.startswith("[") and not rhs.endswith("]"):
                if idx >= len(lines):
                    raise TomlParseError(f"Unterminated array starting near: {raw_line}")
                next_part = _strip_comment(lines[idx]).strip()
                idx += 1
                raw_line = f"{raw_line} {next_part}".strip()
            else:
                break

        if raw_line.startswith("[[") and raw_line.endswith("]]"):
            path = _parse_key_path(raw_line[2:-2])
            target = root
            for key in path[:-1]:
                node = target.setdefault(key, {})
                if isinstance(node, list):
                    node = node[-1]
                target = node
            arr = target.setdefault(path[-1], [])
            if not isinstance(arr, list):
                raise TomlParseError(f"Key {'.'.join(path)} is not an array of tables")
            new_item: Dict[str, Any] = {}
            arr.append(new_item)
            current_table = new_item
        elif raw_line.startswith("[") and raw_line.endswith("]"):
            path = _parse_key_path(raw_line[1:-1])
            target = root
            for key in path:
                node = target.get(key)
                if node is None:
                    node = {}
                    target[key] = node
                elif isinstance(node, list):
                    if not node:
                        raise TomlParseError(f"Empty array table before {'.'.join(path)}")
                    node = node[-1]
                elif not isinstance(node, dict):
                    raise TomlParseError(f"Key conflict at table {'.'.join(path)}")
                target = node
            current_table = target
        else:
            key_raw, val_raw = _split_key_value(raw_line)
            path = _parse_key_path(key_raw)
            target = current_table
            for key in path[:-1]:
                node = target.setdefault(key, {})
                if not isinstance(node, dict):
                    raise TomlParseError(f"Key {key!r} is not a table")
                target = node
            leaf = path[-1]
            if leaf in target:
                raise TomlParseError(f"Duplicate key {'.'.join(path)}")
            target[leaf] = _parse_value(val_raw)

    return root


def loads_toml(text: str) -> Dict[str, Any]:
    """Parse TOML text into a Python dictionary."""
    if _stdlib_tomllib is not None:
        try:
            return _stdlib_tomllib.loads(text)
        except Exception as exc:
            raise TomlParseError(str(exc)) from exc
    return _fallback_loads(text)


def dump_toml_string(value: str) -> str:
    """Format a Python string as a quoted TOML basic string."""
    escaped = (
        value.replace("\\", "\\\\")
        .replace('"', '\\"')
        .replace("\b", "\\b")
        .replace("\t", "\\t")
        .replace("\n", "\\n")
        .replace("\f", "\\f")
        .replace("\r", "\\r")
    )
    return f'"{escaped}"'
