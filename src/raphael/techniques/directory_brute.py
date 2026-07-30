#!/usr/bin/env python3
"""
directory_brute — Directory/file enumeration via gobuster dir mode.
Outputs gobuster raw output for the parse_directory_brute parser.

CLI: python3 -m raphael.techniques.directory_brute http://example.com
"""
import argparse, subprocess, sys, os


def find_wordlist() -> str:
    paths = [
        "/usr/share/dirb/wordlists/common.txt",
        "/usr/share/wordlists/dirb/common.txt",
        "/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt",
        "/usr/share/seclists/Discovery/Web-Content/common.txt",
    ]
    for p in paths:
        if os.path.exists(p):
            return p
    return "/usr/share/dirb/wordlists/common.txt"


def main():
    a = argparse.ArgumentParser(description="Directory enumeration via gobuster")
    a.add_argument("target", help="Target URL (e.g. http://example.com)")
    a.add_argument("--wordlist", help="Wordlist path", default=None)
    a.add_argument("--extensions", help="File extensions (e.g. php,txt,zip)", default="php")
    a.add_argument("--threads", type=int, default=30)
    args = a.parse_args()

    target = args.target
    if not target.startswith("http"):
        target = f"http://{target}"
    if not target.endswith("/"):
        target += "/"

    wordlist = args.wordlist or find_wordlist()

    cmd = [
        "gobuster", "dir",
        "-u", target,
        "-w", wordlist,
        "-t", str(args.threads),
        "-x", args.extensions,
        "-q", "--no-color",
    ]

    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
    except (subprocess.TimeoutExpired, FileNotFoundError) as e:
        print(f"Gobuster error: {e}", file=sys.stderr)
        sys.exit(1)

    sys.stdout.write(r.stdout)
    if r.stderr:
        sys.stderr.write(r.stderr)


if __name__ == "__main__":
    main()
