#!/usr/bin/env python3
"""
fast_port_scan — concurrent TCP port scanning using asyncio.
50-100x faster than sequential nmap for common port ranges.

CLI: python3 -m raphael.techniques.fast_port_scan --target 10.0.0.1 --ports 80,443,8080
"""
import argparse, asyncio, json, sys, time, logging

logging.basicConfig(level=logging.INFO, format="%(message)s")
log = logging.getLogger("fast_port_scan")

COMMON_PORTS = [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445,
                993, 995, 1433, 1521, 2049, 3306, 3389, 5432, 5900, 5985,
                5986, 6379, 8080, 8443, 9000, 9090, 27017, 27018, 50070,
                50075, 50090]


async def probe(host, port, timeout=2.0):
    try:
        _, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port), timeout=timeout)
        writer.close()
        await writer.wait_closed()
        return port, True
    except Exception:
        return port, False


async def scan(host, ports, concurrency=200, timeout=2.0):
    sem = asyncio.Semaphore(concurrency)

    async def bounded(p):
        async with sem:
            return await probe(host, p, timeout)

    tasks = [bounded(p) for p in ports]
    results = await asyncio.gather(*tasks)
    open_ports = [p for p, s in results if s]
    closed_ports = [p for p, s in results if not s]
    return open_ports, closed_ports


def main():
    a = argparse.ArgumentParser()
    a.add_argument("--target", required=True)
    a.add_argument("--ports", help="Comma-separated ports (default: common ports)")
    a.add_argument("--concurrency", type=int, default=200)
    a.add_argument("--timeout", type=float, default=2.0)
    a.add_argument("--output", choices=["json", "text"], default="json")
    args = a.parse_args()

    ports = [int(p.strip()) for p in args.ports.split(",")] if args.ports else COMMON_PORTS
    log.info(f"Scanning {args.target} for {len(ports)} ports (c={args.concurrency})")
    t0 = time.time()
    open_ports, closed_ports = asyncio.run(
        scan(args.target, ports, args.concurrency, args.timeout)
    )
    elapsed = time.time() - t0
    log.info(f"Done: {len(open_ports)} open, {len(closed_ports)} closed in {elapsed:.1f}s")

    result = {
        "target": args.target,
        "open_ports": open_ports,
        "closed_ports": closed_ports,
        "elapsed_seconds": round(elapsed, 1),
        "total_probed": len(ports),
    }
    if args.output == "json":
        print(json.dumps(result))
    else:
        print(f"Open ports on {args.target}: {open_ports}")
        print(f"Closed: {len(closed_ports)} ports")


if __name__ == "__main__":
    main()
