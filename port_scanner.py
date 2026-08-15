#!/usr/bin/env python3
"""Multithreaded TCP port scanner with banner grabbing.

Usage:
    python port_scanner.py <target_ip> <port_range> [--timeout SECONDS] [--threads N]

Example:
    python port_scanner.py 127.0.0.1 1-1024
"""
import argparse
import socket
import threading


def scan_port(target: str, port: int, timeout: float, results: list, lock: threading.Lock) -> None:
    """Attempt one TCP connection; on success, grab a banner and record the result."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            # Bounds how long a single filtered/silent port can block this
            # thread — without a timeout, a non-responding host would hang
            # the thread indefinitely instead of moving on.
            sock.settimeout(timeout)
            result = sock.connect_ex((target, port))
            if result != 0:
                return  # non-zero = connection refused/failed -> port is closed/filtered

            banner = "(no banner)"
            try:
                sock.sendall(b"\r\n")
                raw = sock.recv(1024)
                # errors="replace" swaps undecodable bytes for a placeholder
                # instead of raising, since not every service returns valid
                # UTF-8 (e.g. binary protocol handshakes).
                banner = raw.decode("utf-8", errors="replace").strip() or "(empty banner)"
            except (socket.timeout, OSError):
                pass  # port is open but sent nothing back within the timeout — still a valid result

            # The lock is required because every thread appends to the same
            # shared `results` list; without it, two threads could interleave
            # their list-append operations and corrupt or silently drop entries.
            with lock:
                results.append((port, "open", banner))
    except (socket.timeout, ConnectionRefusedError, OSError):
        # Closed or filtered port — expected and common across a port range,
        # not an error worth surfacing. The scan must not crash because of it.
        pass


def parse_port_range(port_range: str) -> range:
    start_str, _, end_str = port_range.partition("-")
    start = int(start_str)
    end = int(end_str) if end_str else start
    return range(start, end + 1)


def main() -> None:
    parser = argparse.ArgumentParser(description="Multithreaded TCP port scanner with banner grabbing")
    parser.add_argument("target", help="Target IP address")
    parser.add_argument("port_range", help="Port range, e.g. 1-1024, or a single port, e.g. 22")
    parser.add_argument("--timeout", type=float, default=1.0, help="Per-port connection timeout in seconds (default: 1.0)")
    parser.add_argument("--threads", type=int, default=200, help="Max concurrent threads (default: 200)")
    args = parser.parse_args()

    ports = parse_port_range(args.port_range)
    results: list[tuple[int, str, str]] = []
    lock = threading.Lock()
    # Caps how many threads run at once so a large range (e.g. 1-65535)
    # doesn't spawn tens of thousands of threads simultaneously.
    semaphore = threading.Semaphore(args.threads)
    threads = []

    def worker(port: int) -> None:
        with semaphore:
            scan_port(args.target, port, args.timeout, results, lock)

    for port in ports:
        t = threading.Thread(target=worker, args=(port,))
        threads.append(t)
        t.start()

    for t in threads:
        t.join()

    results.sort(key=lambda r: r[0])

    print(f"\nScan results for {args.target} (ports {ports.start}-{ports.stop - 1}):\n")
    print(f"{'Port':<8}{'State':<8}{'Banner'}")
    print("-" * 60)
    for port, state, banner in results:
        print(f"{port:<8}{state:<8}{banner}")
    if not results:
        print("No open ports found in range.")
    print(f"\n{len(results)} open port(s) found.")


if __name__ == "__main__":
    main()
