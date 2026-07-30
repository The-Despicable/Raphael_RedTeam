#!/usr/bin/env python3
"""
subdomain_enum — Subdomain enumeration via gobuster DNS mode.
Outputs one subdomain per line for the existing parse_subdomain_list parser.

CLI: python3 -m raphael.techniques.subdomain_enum example.com
"""
import argparse, subprocess, sys, os, tempfile

# Common DNS wordlist paths
WORDLIST_PATHS = [
    "/usr/share/wordlists/dirb/common.txt",
    "/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt",
    "/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt",
    "/usr/share/dns/wordlists/subdomains.txt",
    "/usr/share/wordlists/subdomains.txt",
]


def find_wordlist() -> str:
    for p in WORDLIST_PATHS:
        if os.path.exists(p):
            return p
    # Fallback: minimal inline wordlist
    tmp = tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".txt")
    tmp.write("www\nmail\nftp\nadmin\napi\nblog\nwebmail\nvpn\nssh\ndev\n")
    tmp.write("test\nportal\nremote\nsecure\nsupport\nforum\nwiki\njenkins\n")
    tmp.write("gitlab\ndocker\nkibana\ngrafana\nprometheus\n")
    tmp.close()
    return tmp.name


def main():
    a = argparse.ArgumentParser(description="Subdomain enumeration via gobuster dns")
    a.add_argument("target", help="Domain (e.g. example.com)")
    a.add_argument("--wordlist", help="DNS wordlist path", default=None)
    a.add_argument("--threads", type=int, default=20, help="Gobuster threads")
    args = a.parse_args()

    domain = args.target
    # Strip protocol if accidentally included
    if "://" in domain:
        domain = domain.split("://")[1].split("/")[0]

    wordlist = args.wordlist or find_wordlist()
    is_temp = wordlist not in WORDLIST_PATHS

    cmd = [
        "gobuster", "dns",
        "-d", domain,
        "-w", wordlist,
        "-t", str(args.threads),
        "--no-color",
        "-q",
    ]

    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
    except (subprocess.TimeoutExpired, FileNotFoundError) as e:
        print(f"Gobuster error: {e}", file=sys.stderr)
        sys.exit(1)
    finally:
        if is_temp:
            try:
                os.unlink(wordlist)
            except OSError:
                pass

    # Gobuster DNS outputs: "Found: sub.domain.com"
    for line in r.stdout.splitlines():
        line = line.strip()
        if line.startswith("Found: "):
            sub = line[7:].strip()
            if sub:
                print(sub)
        elif line and "Progress:" not in line:
            # Fallback: print any non-empty line (for other tools)
            pass

    if r.stderr and "error" in r.stderr.lower():
        sys.stderr.write(r.stderr)


if __name__ == "__main__":
    main()
