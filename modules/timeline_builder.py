from datetime import datetime
from collections import defaultdict

SUSPICIOUS_EVENTS = {
    "DeleteTrail": "CRITICAL",
    "StopLogging": "CRITICAL",
    "DeleteBucket": "CRITICAL",
    "DeleteDBInstance": "CRITICAL",
    "CreateUser": "HIGH",
    "AttachUserPolicy": "HIGH",
    "AttachRolePolicy": "HIGH",
    "CreateAccessKey": "HIGH",
    "PutBucketPolicy": "HIGH",
    "RunInstances": "HIGH",
    "DeleteFlowLogs": "HIGH",
    "ConsoleLogin": "MEDIUM",
    "GetSecretValue": "MEDIUM",
    "AssumeRole": "MEDIUM",
    "ListBuckets": "LOW",
    "DescribeInstances": "LOW",
    "ListUsers": "LOW",
}

SEVERITY_COLORS = {
    "CRITICAL": "\033[91m",  # Kırmızı
    "HIGH": "\033[93m",      # Sarı
    "MEDIUM": "\033[94m",    # Mavi
    "LOW": "\033[92m",       # Yeşil
    "INFO": "\033[37m",      # Gri
    "RESET": "\033[0m"
}

def build_timeline(events):
    """Olaylardan zaman çizelgesi oluştur"""
    timeline = {
        "events": [],
        "summary": {
            "total": 0,
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "info": 0
        },
        "actors": defaultdict(int),
        "ips": defaultdict(int),
        "top_events": defaultdict(int)
    }

    # Olayları zamanına göre sırala
    sorted_events = sorted(events, key=lambda x: x.get("event_time", ""))

    for event in sorted_events:
        event_name = event.get("event_name", "")
        severity = SUSPICIOUS_EVENTS.get(event_name, "INFO")
        username = event.get("username", "Unknown")
        source_ip = event.get("source_ip", "Unknown")
        event_time = event.get("event_time", "")
        error_code = event.get("error_code", "")

        # Gece yarısı kontrolü (00:00 - 06:00 UTC)
        is_midnight = False
        try:
            dt = datetime.fromisoformat(event_time.replace("Z", "+00:00"))
            is_midnight = 0 <= dt.hour < 6
            if is_midnight and severity in ["HIGH", "CRITICAL"]:
                severity = "CRITICAL"
        except:
            pass

        timeline_event = {
            "time": event_time,
            "event_name": event_name,
            "severity": severity,
            "username": username,
            "source_ip": source_ip,
            "error_code": error_code,
            "is_midnight": is_midnight,
            "suspicious": severity in ["CRITICAL", "HIGH"]
        }

        timeline["events"].append(timeline_event)
        timeline["summary"][severity.lower()] += 1
        timeline["summary"]["total"] += 1
        timeline["actors"][username] += 1
        timeline["ips"][source_ip] += 1
        timeline["top_events"][event_name] += 1

    # En aktif aktörler ve IP'ler
    timeline["top_actors"] = sorted(
        timeline["actors"].items(),
        key=lambda x: x[1], reverse=True
    )[:5]

    timeline["top_ips"] = sorted(
        timeline["ips"].items(),
        key=lambda x: x[1], reverse=True
    )[:5]

    timeline["top_event_types"] = sorted(
        timeline["top_events"].items(),
        key=lambda x: x[1], reverse=True
    )[:10]

    return timeline


def print_timeline(timeline):
    """Zaman çizelgesini terminale yazdır"""
    c = SEVERITY_COLORS
    reset = c["RESET"]

    print(f"\n{c['CRITICAL']}{'═' * 60}{reset}")
    print(f"{c['CRITICAL']}  CloudForensics — AWS Dijital Adli Analiz{reset}")
    print(f"{c['CRITICAL']}{'═' * 60}{reset}\n")

    # Özet
    s = timeline["summary"]
    print(f"  📊 ÖZET")
    print(f"  {'─' * 40}")
    print(f"  Toplam Olay  : {s['total']}")
    print(f"  {c['CRITICAL']}Critical     : {s['critical']}{reset}")
    print(f"  {c['HIGH']}High         : {s['high']}{reset}")
    print(f"  {c['MEDIUM']}Medium       : {s['medium']}{reset}")
    print(f"  {c['LOW']}Low          : {s['low']}{reset}")
    print()

    # En aktif aktörler
    print(f"  👤 EN AKTİF AKTÖRLER")
    print(f"  {'─' * 40}")
    for actor, count in timeline["top_actors"]:
        print(f"  {actor:<30} {count} olay")
    print()

    # En aktif IP'ler
    print(f"  🌐 EN AKTİF IP'LER")
    print(f"  {'─' * 40}")
    for ip, count in timeline["top_ips"]:
        print(f"  {ip:<30} {count} istek")
    print()

    # Şüpheli olaylar
    suspicious = [e for e in timeline["events"] if e["suspicious"]]
    if suspicious:
        print(f"  {c['CRITICAL']}🚨 ŞÜPHELİ AKTİVİTELER ({len(suspicious)}){reset}")
        print(f"  {'─' * 40}")
        for event in suspicious[-20:]:  # Son 20 şüpheli olay
            sev_color = c.get(event["severity"], c["INFO"])
            midnight = " 🌙 GECE YARISI!" if event["is_midnight"] else ""
            error = f" ❌ {event['error_code']}" if event["error_code"] else ""
            print(f"  {sev_color}[{event['severity']:<8}]{reset} "
                  f"{event['time'][:19]} | "
                  f"{event['event_name']:<30} | "
                  f"{event['username']:<20} | "
                  f"{event['source_ip']}{midnight}{error}")
    print()