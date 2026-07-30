#!/usr/bin/env python3
"""
ssrf_check — Server-Side Request Forgery detection via nuclei SSRF templates.
Outputs nuclei JSON for the parse_nuclei_vuln parser.

CLI: python3 -m raphael.techniques.ssrf_check http://example.com
"""
import argparse, json, subprocess, sys


def main():
    a = argparse.ArgumentParser(description="SSRF detection via nuclei")
    a.add_argument("target", help="Target URL (e.g. http://example.com)")
    args = a.parse_args()

    target = args.target
    if not target.startswith("http"):
        target = f"http://{target}"

    cmd = [
        "nuclei", "-target", target,
        "-t", "http/misconfiguration/",
        "-tags", "ssrf",
        "-json", "-silent",
        "-timeout", "10",
    ]

    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
    except (subprocess.TimeoutExpired, FileNotFoundError) as e:
        print(f"Nuclei error: {e}", file=sys.stderr)
        sys.exit(1)

    sys.stdout.write(r.stdout)


if __name__ == "__main__":
    main()
