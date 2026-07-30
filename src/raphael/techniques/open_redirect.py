#!/usr/bin/env python3
"""open_redirect — Open Redirect via nuclei. Outputs JSON for parse_nuclei_vuln."""
import argparse, subprocess, sys
def main():
    a = argparse.ArgumentParser()
    a.add_argument("target", help="Target URL")
    args = a.parse_args()
    target = args.target if args.target.startswith("http") else f"http://{args.target}"
    try:
        r = subprocess.run(["nuclei","-target",target,"-t","http/vulnerabilities/","-tags","redirect","-json","-silent","-timeout","10"], capture_output=True, text=True, timeout=120)
    except (subprocess.TimeoutExpired, FileNotFoundError) as e:
        print(f"Nuclei error: {e}", file=sys.stderr); sys.exit(1)
    sys.stdout.write(r.stdout)
if __name__ == "__main__": main()
