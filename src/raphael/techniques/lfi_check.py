#!/usr/bin/env python3
"""
lfi_check — Local File Inclusion detection via nuclei LFI templates.
Outputs nuclei JSON for the parse_nuclei_vuln parser.

CLI: python3 -m raphael.techniques.lfi_check http://example.com
"""
import argparse, json, subprocess, sys, os


def main():
    a = argparse.ArgumentParser(description="LFI detection via nuclei")
    a.add_argument("target", help="Target URL (e.g. http://example.com/page.php?file=)")
    args = a.parse_args()

    target = args.target
    if not target.startswith("http"):
        target = f"http://{target}"

    cmd = [
        "nuclei", "-target", target,
        "-t", "http/vulnerabilities/other/",
        "-tags", "lfi",
        "-json", "-silent",
        "-timeout", "10",
    ]

    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
    except (subprocess.TimeoutExpired, FileNotFoundError) as e:
        print(f"Nuclei error: {e}", file=sys.stderr)
        sys.exit(1)

    # Output nuclei JSON lines verbatim — parser handles it
    sys.stdout.write(r.stdout)


if __name__ == "__main__":
    main()
