"""CLI: ``dynamicfeed-verify`` — fetch a live signed verdict and verify it, or verify a saved response."""
from __future__ import annotations

import json
import sys

from . import DEFAULT_BASE, _strict_loads, verify, verify_live


def main() -> int:
    args = sys.argv[1:]
    if args and args[0] in ("-h", "--help"):
        print("usage:\n"
              "  dynamicfeed-verify [BASE_URL]          fetch a live signed verdict and verify it\n"
              "  dynamicfeed-verify - [BASE_URL] < response.json   verify saved bytes with lifecycle policy\n"
              "  default BASE_URL = https://dynamicfeed.ai   ·   spec: https://dynamicfeed.ai/standard")
        return 0
    if args and args[0] == "-":
        env = _strict_loads(sys.stdin.read())
        base = args[1].rstrip("/") if len(args) > 1 else DEFAULT_BASE
        res = verify(env, base=base)
    else:
        base = args[0].rstrip("/") if args else DEFAULT_BASE
        print(f"requesting a live signed verdict from {base}/v1/awareness ...")
        _env, res = verify_live(base)
    if res.get("ok"):
        extra = ""
        if res.get("verdict"):
            extra += f" · verdict={res['verdict']}"
        if res.get("snapshot_id"):
            extra += f" · snapshot={res['snapshot_id']}"
        if res.get("ephemeral"):
            extra += " · EPHEMERAL key"
        print(f"✅ POLICY ACCEPTED — signature valid · lifecycle={res.get('lifecycle_status')} · key={res['key_id']}{extra}")
        return 0
    if res.get("crypto_valid"):
        print(f"△ CRYPTOGRAPHICALLY VALID, LIFECYCLE REJECTED — key={res.get('key_id')} · "
              f"status={res.get('lifecycle_status', 'unknown')} · {res.get('error')}")
        return 1
    print(f"✗ INVALID — {res.get('error')}")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
