import ipaddress
import socket


def classify_ip(ip):
    try:
        address = ipaddress.ip_address(ip)

        return {
            "type": "ipv4" if address.version == 4 else "ipv6",
            "scope": (
                "loopback" if address.is_loopback
                else "private" if address.is_private
                else "global" if address.is_global
                else "other"
            ),
            "valid": True
        }

    except ValueError:
        return {
            "type": "unknown",
            "scope": "invalid",
            "valid": False
        }


def enrich_ip(ip):
    result = classify_ip(ip)

    enrichment = {
        "observable": ip,
        "observable_type": result["type"],
        "scope": result["scope"],
        "valid": result["valid"],
        "hostname": None
    }

    if result["valid"]:
        try:
            hostname = socket.gethostbyaddr(ip)[0]
            enrichment["hostname"] = hostname
        except (socket.herror, socket.gaierror, OSError):
            pass

    return enrichment


def enrich_iocs(iocs):
    results = {
        "ips": [],
        "domains": [],
        "urls": [],
        "hashes": []
    }

    for ip in iocs.get("ipv4", []):
        results["ips"].append(enrich_ip(ip))

    for ip in iocs.get("ipv6", []):
        results["ips"].append(enrich_ip(ip))

    for domain in iocs.get("domains", []):
        results["domains"].append({
            "observable": domain,
            "observable_type": "domain"
        })

    for url in iocs.get("urls", []):
        results["urls"].append({
            "observable": url,
            "observable_type": "url"
        })

    for sha256 in iocs.get("sha256", []):
        results["hashes"].append({
            "observable": sha256,
            "hash_type": "sha256"
        })

    for sha1 in iocs.get("sha1", []):
        results["hashes"].append({
            "observable": sha1,
            "hash_type": "sha1"
        })

    for md5 in iocs.get("md5", []):
        results["hashes"].append({
            "observable": md5,
            "hash_type": "md5"
        })

    return results
