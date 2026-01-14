#!/usr/bin/env python3
"""
convert ASCII string into a little-endian hex literal
"""
import sys

def to_little_endian_hex(s: str) -> str:
    b = s.encode("ascii")          # ASCII bytes
    le = b[::-1]                   # reverse for little-endian representation
    return "0x" + le.hex()         # lowercase hex, no separators


def main() -> int:
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <ascii_string>", file=sys.stderr)
        return 2

    s = sys.argv[1]
    try:
        s.encode("ascii")
    except UnicodeEncodeError:
        print("Error: input must be ASCII.", file=sys.stderr)
        return 1

    print(to_little_endian_hex(s))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
