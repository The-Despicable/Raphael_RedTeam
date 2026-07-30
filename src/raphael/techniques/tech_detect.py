#!/usr/bin/env python3
"""
tech_detect — Technology stack identification via whatweb.
Outputs raw whatweb output for the existing parse_tech_fingerprint parser.

CLI: python3 -m raphael.techniques.tech_detect http://example.com
"""
import argparse, subprocess, sys


def main():
    a = argparse.ArgumentParser(description="Technology stack detection via whatweb")
    a.add_argument("target", help="Target URL (e.g. http://example.com)")
    a.add_argument("--aggression", type=int, default=1, choices=[1, 3],
                   help="Whatweb aggression level (1=stealth, 3=aggressive)")
    args = a.parse_args()

    target = args.target
    if not target.startswith("http"):
        target = f"http://{target}"

    cmd = ["whatweb", "--color=never", f"--aggression={args.aggression}", target]

    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
    except (subprocess.TimeoutExpired, FileNotFoundError) as e:
        print(f"Whatweb error: {e}", file=sys.stderr)
        sys.exit(1)

    sys.stdout.write(r.stdout)
    if r.stderr:
        sys.stderr.write(r.stderr)


if __name__ == "__main__":
    main()
