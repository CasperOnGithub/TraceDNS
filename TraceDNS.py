import sys
import socket
from datetime import datetime
import dns.message
import dns.query
import dns.rdatatype

VERSION = "0.1.1" ### Release Version

### OUTPUT ###

def banner ():
    print(r"""

TraceDNS v0.1.1
DNS / Infrastructure

DISCLAIMER: TraceDNS performs DNS lookups only. No hacky hacky
""")

def section(title):
    print()
    print("=" * 60)
    print(f" {title}")
    print("=" * 60)

def record(label, value):
    print(f"{label:<12} {value}")

### DNS ###

DNS_SERVER = "8.8.8.8"

def query_dns(domain, record_type): ### Prevent timeouts on packets
    try:
        rdtype = dns.rdatatype.from_text(record_type)
        q = dns.message.make_query(domain, rdtype)
        response = dns.query.udp(q, DNS_SERVER, timeout=3)
        
        results = []
        for rrset in response.answer:
            for item in rrset:
                results.append(item.to_text())
        return results
    except Exception:
        return []

### HOST RESOLUTION ###

def resolve_host(hostname): ### Hostname to IPv4/IPv6
    try: 
        results = socket.getaddrinfo(
            hostname,
            None,
            socket.AF_UNSPEC,
            socket.SOCK_STREAM
        )

        return sorted({
            result[4][0]
            for result in results
         })
    except socket.gaierror:
        return []

### DNS RECORDS ###

def show_records(domain):
    record_types = [
        "A",
        "AAAA",
        "CNAME",
        "MX",
        "NS",
        "TXT",
        "SOA",
    ]

    section("DNS RECORDS")
    found_any = False
    for record_type in record_types:
        results = query_dns(domain, record_type)
        if not results:
            continue

        found_any = True
        print(f"\n[{record_type}]")
        for result in results:
            print(f"  {result}")

    if not found_any:
        print("NO DNS RECORDS HAVE BEEN FOUND.")

### SPF (is anyone actually reading the entire thing?) ###

def show_spf(domain):
    section("SPF")
    txt_records = query_dns(domain, "TXT")
    spf_records = []

    for result in txt_records:
        if "v=spf1" in result.lower():
            spf_records.append(result)

    if not spf_records:
        print("NO SPF RECORDS FOUND")
        return

    for result in spf_records:
        print(f" {result}")

### MAIL ###

def show_mx_infrastructure(domain):
    section("MAIL")
    mx_records = query_dns(domain, "MX")
    if not mx_records:
        print("NO MX RECORDS FOUND")
        return

    for mx in mx_records:
        parts = mx.split()

        if len(parts) < 2:
            continue
        priority = parts[0]
        hostname = parts[1].rstrip(".")
        print()
        print(f" MX HOST:  {hostname}")
        print(f" PRIORITY: {priority}")

        ips = resolve_host(hostname)
        if not ips:
            print("IP: NONE")
        else:
            for ip in ips:
                print(f"IP: {ip}")

### NAMESERVER INFRA ###

def show_ns_infrastructure(domain):
    section("NAMESERVER INFRA")
    ns_records = query_dns(domain, "NS")

    if not ns_records:
        print("NO NAMESERVER FOUND")
        return
    for ns in ns_records:
        hostname = ns.rstrip(".")
        print()
        print(f"NAMESERVER: {hostname}")
        ips = resolve_host(hostname)

        if not ips:
            print("IP: COULD NOT FIND")
        else:
            for ip in ips:
                print(f"IP: {ip}")

### SUMMARY ### (Remember to clean this section up)

def show_summary(domain):
    section("SUMMARY")
    a_records = query_dns(domain, "A")
    aaaa_records = query_dns(domain, "AAAA")
    cname_records = query_dns(domain, "CNAME")
    mx_records = query_dns(domain, "MX")
    ns_records = query_dns(domain, "NS")
    txt_records = query_dns(domain, "TXT")
    soa_records = query_dns(domain, "SOA")
    ### ^^^ For overview (Buttom one too)
    record("Domain", domain)
    record("A records", len(a_records))
    record("AAAA records", len(aaaa_records))
    record("CNAME records", len(cname_records))
    record("MX records", len(mx_records))
    record("NS records", len(ns_records))
    record("TXT records", len(txt_records))
    record("SOA records", len(soa_records))

    print()
    print("Mode:")
    print("DNS LOOKUPS")
    print()
    print("IMPORTANT:")
    print("DNS RELATIONSHIPS DO NOT PROVE OWNERSHIP!")
    print("ALWAYS VERIFY WITH ANOTHER SOURCE BEFORE TAKING ACTION!")

### MAIN ###

def main():
    if len(sys.argv) < 2:
        print("Usage: python tracedns.py <domain> [--version]")
        sys.exit(1)

    if "--version" in sys.argv:
        print(f"TraceDNS {VERSION}")
        sys.exit(0)

    domain = sys.argv[1].strip().lower().rstrip(".")

    banner()
    print(f"Target:   {domain}")
    print(
        "Started:  "
        f"{datetime.now().astimezone().strftime('%Y-%m-%d %H:%M:%S %Z')}"
    )

    show_records(domain)
    show_spf(domain)
    show_mx_infrastructure(domain)
    show_ns_infrastructure(domain)
    show_summary(domain)


### THE END ###

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\nInterrupted.")
        sys.exit(1)
