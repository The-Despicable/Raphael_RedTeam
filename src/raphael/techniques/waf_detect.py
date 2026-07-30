#!/usr/bin/env python3
"""
waf_detect — WAF fingerprinting via nuclei WAF detection templates.
Outputs wafw00f-compatible format for the existing parse_waf_detect parser.

CLI: python3 -m raphael.techniques.waf_detect http://example.com
"""
import argparse, json, subprocess, sys, urllib.parse


def run_nuclei_waf(target: str) -> list[str]:
    """Run nuclei WAF detection, return list of detected WAF names."""
    try:
        r = subprocess.run(
            ["nuclei", "-target", target, "-t", "http/technologies/waf-detect.yaml",
             "-json", "-silent", "-timeout", "10"],
            capture_output=True, text=True, timeout=60
        )
    except (subprocess.TimeoutExpired, FileNotFoundError) as e:
        print(f"Nuclei error: {e}", file=sys.stderr)
        return []

    waf_names = []
    for line in r.stdout.strip().splitlines():
        if not line.strip():
            continue
        try:
            data = json.loads(line)
            info = data.get("info", {})
            name = info.get("name", "") or data.get("matched-at", "")
            if name:
                waf_names.append(name)
        except json.JSONDecodeError:
            pass
    return waf_names


def main():
    a = argparse.ArgumentParser(description="WAF fingerprinting via nuclei")
    a.add_argument("target", help="Target URL (e.g. http://example.com)")
    args = a.parse_args()

    target = args.target
    if not target.startswith("http"):
        target = f"http://{target}"

    wafs = run_nuclei_waf(target)

    if wafs:
        for w in wafs:
            print(f"WAF {w} detected")
    else:
        # Still print empty to indicate scan completed
        sys.stderr.write("No WAF detected via nuclei\n")


if __name__ == "__main__":
    main()
