#!/usr/bin/env python3
"""
sqli_check — Deep SQL injection testing via sqlmap.
Outputs sqlmap raw output for the existing parse_sqlmap_result parser.
Complements mass_payload_test: mass test finds candidates → sqli_check confirms.

CLI: python3 -m raphael.techniques.sqli_check http://example.com/page?id=1
"""
import argparse, subprocess, sys, os


def main():
    a = argparse.ArgumentParser(description="SQL injection detection via sqlmap")
    a.add_argument("target", help="Target URL with parameter (e.g. http://x/page.php?id=1)")
    a.add_argument("--level", type=int, default=1, choices=[1, 2, 3, 4, 5],
                   help="Sqlmap level (1=fast, 5=deep)")
    a.add_argument("--risk", type=int, default=1, choices=[1, 2, 3],
                   help="Sqlmap risk (1=low, 3=high)")
    a.add_argument("--batch", action="store_true", default=True,
                   help="Non-interactive mode")
    args = a.parse_args()

    target = args.target
    if not target.startswith("http"):
        target = f"http://{target}"

    cmd = [
        "sqlmap",
        "-u", target,
        f"--level={args.level}",
        f"--risk={args.risk}",
        "--batch" if args.batch else "--no-batch",
        "--random-agent",
        "--time-sec=5",
        "--output-dir=/tmp/sqlmap_out",
    ]
    # Flatten boolean flags
    cmd = [c for c in cmd if not c.startswith("--no-")]

    try:
        r = subprocess.run(
            cmd, capture_output=True, text=True, timeout=600
        )
    except (subprocess.TimeoutExpired, FileNotFoundError) as e:
        print(f"Sqlmap error: {e}", file=sys.stderr)
        sys.exit(1)

    sys.stdout.write(r.stdout)
    if r.stderr:
        sys.stderr.write(r.stderr)


if __name__ == "__main__":
    main()
