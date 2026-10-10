#!/usr/bin/env python3
"""Build the Iran-IP address list.

Iran-IP = (IPv4 space registered to IR at the RIRs)
        + (IPv4 prefixes announced in BGP by ASNs registered in IR)
        + address-lists/Iran-IP-extra.txt   (optional, hand-maintained)
        - address-lists/Iran-IP-exclude.txt (optional, hand-maintained)

The registry list alone misses space that Iranian networks announce but that
is registered under another country code (for example Respina 5.160.0.0/16).

Sources:
  registry  RIPEstat "country-resource-list" (RIPE NCC, built from the RIR
            statistics files). If RIPEstat is down or its answer looks wrong,
            the ipverse copy of the same data is used instead and the run
            prints a warning. When both answer they are compared, and a large
            disagreement stops the run.
  BGP       ipverse as-metadata + as-ip-blocks.

Outputs (in address-lists/):
  Iran-IP.txt  one prefix per line, last line "#END <count>". Routers read
               this with "/tool fetch output=user" and apply only the
               differences, so the list is never empty during an update.
  Iran-IP.rsc  legacy import file (remove + add) for routers that still run
               the old update script.

Nothing is written unless every sanity check passes, so a broken download
can never publish a broken list. Standard library only.
"""
import concurrent.futures
import csv
import io
import ipaddress
import json
import pathlib
import sys
import time
import urllib.error
import urllib.request

RIPESTAT_URL = (
    "https://stat.ripe.net/data/country-resource-list/data.json"
    "?resource=ir&v4_format=prefix&sourceapp=mikrotik-scripts"
)
RAW = "https://raw.githubusercontent.com/ipverse"
RIR_URLS = [  # ipverse renamed rir-ip to country-ip-blocks in January 2026
    RAW + "/country-ip-blocks/master/country/ir/ipv4-aggregated.txt",
    RAW + "/rir-ip/master/country/ir/ipv4-aggregated.txt",
]
AS_CSV_URLS = [
    RAW + "/as-metadata/master/as.csv",
    RAW + "/asn-info/master/as.csv",
]
AS_PREFIX_URLS = [
    RAW + "/as-ip-blocks/master/as/{asn}/ipv4-aggregated.txt",
    RAW + "/asn-ip/master/as/{asn}/ipv4-aggregated.txt",
]

OUT_DIR = pathlib.Path(__file__).resolve().parent.parent / "address-lists"
LIST_NAME = "Iran-IP"

# Sanity limits. The list was 10.8M addresses / 1747 prefixes from the
# registry alone and 11.0M / 1799 with BGP (October 2026).
MIN_PREFIXES = 1000
MIN_ADDRESSES = 9_000_000
MAX_ADDRESSES = 14_000_000
MAX_TXT_BYTES = 60_000  # RouterOS "/tool fetch output=user" holds about 64 KB
MUST_CONTAIN = ["78.38.48.232", "217.218.127.127", "5.160.154.1", "81.30.108.171"]
MUST_NOT_CONTAIN = ["8.8.8.8", "1.1.1.1", "65.108.48.50", "185.252.40.163"]
MAX_FAILED_ASN_SHARE = 0.03
MIN_REGISTRY_ADDRESSES = 9_000_000  # below this a registry answer is not believed
MAX_REGISTRY_MISMATCH = 0.02  # RIPEstat vs ipverse, share of addresses


def fetch(url, tries=4):
    """Return the body as text, or None when the server answers 404."""
    last = None
    for attempt in range(tries):
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "mikrotik-scripts list builder"})
            with urllib.request.urlopen(req, timeout=40) as resp:
                return resp.read().decode("utf-8", "replace")
        except urllib.error.HTTPError as err:
            if err.code == 404:
                return None
            last = err
        except Exception as err:  # network errors, timeouts
            last = err
        time.sleep(2 * (attempt + 1))
    raise RuntimeError(f"download failed: {url}: {last}")


def fetch_first(urls):
    """Try each mirror in turn; return the first body that exists."""
    error = None
    for url in urls:
        try:
            body = fetch(url)
        except RuntimeError as err:
            error = err
            continue
        if body is not None:
            return body
    if error:
        raise error
    return None


def parse_prefixes(text):
    nets = []
    for line in (text or "").splitlines():
        line = line.split("#", 1)[0].strip()
        if not line:
            continue
        try:
            net = ipaddress.ip_network(line, strict=False)
        except ValueError:
            continue
        if net.version != 4 or net.prefixlen < 8:
            continue
        if net.is_private or net.is_multicast or net.is_loopback or net.is_reserved or net.is_link_local:
            continue
        nets.append(net)
    return nets


def size(nets):
    return sum(n.num_addresses for n in ipaddress.collapse_addresses(nets))


def parse_ripestat(text):
    """IPv4 prefixes from a RIPEstat country-resource-list answer."""
    entries = json.loads(text)["data"]["resources"]["ipv4"]
    nets = []
    for entry in entries:
        if "-" in entry:  # a range, when the API ignores v4_format=prefix
            first, last = (ipaddress.ip_address(part.strip()) for part in entry.split("-", 1))
            nets.extend(parse_prefixes("\n".join(map(str, ipaddress.summarize_address_range(first, last)))))
        else:
            nets.extend(parse_prefixes(entry))
    return nets


def warn(message):
    print(f"::warning::{message}")  # shown as a warning on the GitHub Actions run


def note(message):
    print(f"::notice::{message}")  # shown on the run page without opening the log


def registry_prefixes():
    """Return (prefixes, source name). RIPEstat first, ipverse as the backup."""
    ripestat = ipverse = None
    try:
        ripestat = parse_ripestat(fetch(RIPESTAT_URL) or "")
        if size(ripestat) < MIN_REGISTRY_ADDRESSES:
            warn(f"RIPEstat returned only {size(ripestat)} addresses, ignoring it")
            ripestat = None
    except Exception as err:  # download, JSON or format problem
        warn(f"RIPEstat registry download failed: {err}")
    try:
        ipverse = parse_prefixes(fetch_first(RIR_URLS))
        if size(ipverse) < MIN_REGISTRY_ADDRESSES:
            warn(f"ipverse returned only {size(ipverse)} registry addresses, ignoring it")
            ipverse = None
    except Exception as err:
        warn(f"ipverse registry download failed: {err}")

    if ripestat and ipverse:
        both = size(ripestat + ipverse)
        only_ripestat = both - size(ipverse)
        only_ipverse = both - size(ripestat)
        note(f"registry: RIPEstat {size(ripestat)} addresses, ipverse {size(ipverse)}; "
             f"{only_ripestat} only in RIPEstat, {only_ipverse} only in ipverse")
        if only_ripestat + only_ipverse > size(ripestat) * MAX_REGISTRY_MISMATCH:
            sys.exit("ERROR: RIPEstat and ipverse disagree about the registry space")
        return ripestat, "RIPEstat"
    if ripestat:
        return ripestat, "RIPEstat"
    if ipverse:
        warn("registry space taken from ipverse (backup source)")
        return ipverse, "ipverse"
    sys.exit("ERROR: no registry source answered")


def read_optional(name):
    path = OUT_DIR / name
    return parse_prefixes(path.read_text()) if path.exists() else []


def subtract(nets, holes):
    """Remove every network in `holes` from `nets`."""
    for hole in holes:
        kept = []
        for net in nets:
            if hole.subnet_of(net):
                kept.extend(net.address_exclude(hole) if hole != net else [])
            elif net.subnet_of(hole):
                continue
            else:
                kept.append(net)
        nets = kept
    return nets


def fmt(net):
    # RouterOS shows a /32 entry as a bare address; match that exactly.
    return str(net.network_address) if net.prefixlen == 32 else str(net)


def main():
    rir, rir_source = registry_prefixes()

    as_csv = fetch_first(AS_CSV_URLS)
    if not as_csv:
        sys.exit("ERROR: ASN metadata is missing")
    asns = [row["asn"] for row in csv.DictReader(io.StringIO(as_csv)) if row.get("country-code") == "IR"]
    if len(asns) < 300:
        sys.exit(f"ERROR: only {len(asns)} Iranian ASNs found")

    def one(asn):
        try:
            return parse_prefixes(fetch_first([u.format(asn=asn) for u in AS_PREFIX_URLS]))
        except RuntimeError:
            return None

    bgp, failed, announcing = [], 0, 0
    with concurrent.futures.ThreadPoolExecutor(max_workers=16) as pool:
        for nets in pool.map(one, asns):
            if nets is None:
                failed += 1
            elif nets:
                announcing += 1
                bgp.extend(nets)
    if failed > len(asns) * MAX_FAILED_ASN_SHARE:
        sys.exit(f"ERROR: {failed} of {len(asns)} ASN downloads failed")
    if announcing < 300:
        sys.exit(f"ERROR: only {announcing} Iranian ASNs have announced prefixes")

    extra = read_optional(LIST_NAME + "-extra.txt")
    exclude = read_optional(LIST_NAME + "-exclude.txt")

    merged = list(ipaddress.collapse_addresses(rir + bgp + extra))
    merged = sorted(ipaddress.collapse_addresses(subtract(merged, exclude)))
    total = sum(n.num_addresses for n in merged)

    def covered(ip):
        addr = ipaddress.ip_address(ip)
        return any(addr in n for n in merged)

    problems = []
    if len(merged) < MIN_PREFIXES:
        problems.append(f"only {len(merged)} prefixes")
    if not MIN_ADDRESSES <= total <= MAX_ADDRESSES:
        problems.append(f"{total} addresses is outside {MIN_ADDRESSES}..{MAX_ADDRESSES}")
    problems += [f"{ip} is missing" for ip in MUST_CONTAIN if not covered(ip)]
    problems += [f"{ip} must not be in the list" for ip in MUST_NOT_CONTAIN if covered(ip)]

    lines = [fmt(n) for n in merged]
    txt = "\n".join(lines) + f"\n#END {len(lines)}\n"
    if len(txt.encode()) > MAX_TXT_BYTES:
        problems.append(f"{LIST_NAME}.txt is {len(txt.encode())} bytes, over the {MAX_TXT_BYTES} byte router limit")
    if problems:
        sys.exit("ERROR: " + "; ".join(problems))

    rsc = [f"/ip firewall address-list remove [find list={LIST_NAME}]"]
    rsc += [f"/ip firewall address-list add list={LIST_NAME} address={line} comment=RIPE" for line in lines]

    OUT_DIR.mkdir(exist_ok=True)
    (OUT_DIR / f"{LIST_NAME}.txt").write_text(txt)
    (OUT_DIR / f"{LIST_NAME}.rsc").write_text("\n".join(rsc) + "\n")

    rir_total = size(rir)
    note(
        f"{LIST_NAME}: {len(lines)} prefixes, {total} addresses "
        f"(registry {rir_total} from {rir_source}, +{total - rir_total} from {announcing} announcing ASNs of {len(asns)}, "
        f"{failed} ASN downloads failed, {len(extra)} extra, {len(exclude)} excluded)"
    )


if __name__ == "__main__":
    main()
