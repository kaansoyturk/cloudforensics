import requests
import time

# Önbellek
ip_cache = {}

def investigate_ip(ip):
    """IP adresini araştır"""
    if ip in ip_cache:
        return ip_cache[ip]

    result = {
        "ip": ip,
        "country": "Bilinmiyor",
        "city": "Bilinmiyor",
        "isp": "Bilinmiyor",
        "is_tor": False,
        "is_vpn": False,
        "is_datacenter": False,
        "threat_score": 0,
        "threat_types": [],
        "abuse_reports": 0
    }

    # Yerel IP kontrolü
    if ip.startswith(("192.168.", "10.", "172.16.", "127.", "::1")):
        result["country"] = "Yerel Ağ"
        result["city"] = "Yerel"
        result["isp"] = "Internal"
        ip_cache[ip] = result
        return result

    # AWS servisleri
    if ip.endswith(".amazonaws.com") or "aws" in ip.lower():
        result["isp"] = "Amazon AWS"
        result["is_datacenter"] = True
        ip_cache[ip] = result
        return result

    try:
        # ip-api.com ile konum bilgisi
        response = requests.get(
            f"http://ip-api.com/json/{ip}?fields=country,city,isp,org,as,proxy,hosting",
            timeout=3
        )
        if response.status_code == 200:
            data = response.json()
            result["country"] = data.get("country", "Bilinmiyor")
            result["city"] = data.get("city", "Bilinmiyor")
            result["isp"] = data.get("isp", "Bilinmiyor")
            result["is_vpn"] = data.get("proxy", False)
            result["is_datacenter"] = data.get("hosting", False)

            # Threat score hesapla
            if result["is_tor"]:
                result["threat_score"] += 80
                result["threat_types"].append("Tor Exit Node")
            if result["is_vpn"]:
                result["threat_score"] += 40
                result["threat_types"].append("VPN/Proxy")
            if result["is_datacenter"]:
                result["threat_score"] += 20
                result["threat_types"].append("Datacenter IP")

        time.sleep(0.5)  # Rate limiting

    except Exception as e:
        result["error"] = str(e)

    ip_cache[ip] = result
    return result


def investigate_multiple_ips(ips):
    """Birden fazla IP'yi araştır"""
    results = {}
    unique_ips = list(set(ips))

    print(f"\n  🌐 {len(unique_ips)} benzersiz IP araştırılıyor...")

    for i, ip in enumerate(unique_ips):
        if ip and ip != "Unknown":
            results[ip] = investigate_ip(ip)
            print(f"  [{i+1}/{len(unique_ips)}] {ip} → {results[ip]['country']}")

    return results


def get_suspicious_ips(ip_results):
    """Şüpheli IP'leri filtrele"""
    suspicious = []
    for ip, data in ip_results.items():
        if data.get("threat_score", 0) > 0 or data.get("is_tor") or data.get("is_vpn"):
            suspicious.append({
                "ip": ip,
                "country": data.get("country"),
                "isp": data.get("isp"),
                "threat_score": data.get("threat_score", 0),
                "threat_types": data.get("threat_types", [])
            })
    return sorted(suspicious, key=lambda x: x["threat_score"], reverse=True)