from collections import defaultdict
from datetime import datetime, timezone

ATTACK_PATTERNS = {
    "credential_access": {
        "events": ["ConsoleLogin", "GetSecretValue", "GetSessionToken"],
        "description": "Kimlik bilgisi erişim girişimi",
        "severity": "HIGH"
    },
    "defense_evasion": {
        "events": ["DeleteTrail", "StopLogging", "DeleteFlowLogs", "PutEventSelectors"],
        "description": "Savunma mekanizmalarını devre dışı bırakma",
        "severity": "CRITICAL"
    },
    "persistence": {
        "events": ["CreateUser", "CreateAccessKey", "AttachUserPolicy", "AttachRolePolicy"],
        "description": "Kalıcılık sağlama girişimi",
        "severity": "HIGH"
    },
    "discovery": {
        "events": ["ListBuckets", "ListUsers", "DescribeInstances", "ListRoles", "GetAccountSummary"],
        "description": "Ortam keşfi",
        "severity": "MEDIUM"
    },
    "exfiltration": {
        "events": ["GetObject", "CopyObject", "CreateBucket", "PutBucketPolicy"],
        "description": "Veri sızdırma girişimi",
        "severity": "HIGH"
    },
    "impact": {
        "events": ["DeleteBucket", "DeleteDBInstance", "TerminateInstances", "DeleteVolume"],
        "description": "Yıkıcı eylem",
        "severity": "CRITICAL"
    }
}

def analyze_threats(timeline_events, ip_results):
    """Tehdit analizi yap"""
    threats = {
        "attack_patterns": [],
        "anomalies": [],
        "risk_score": 0,
        "compromised_accounts": [],
        "attack_timeline": []
    }

    # Olay sayaçları
    event_counts = defaultdict(int)
    user_events = defaultdict(list)
    ip_events = defaultdict(list)
    failed_logins = defaultdict(int)

    for event in timeline_events:
        event_name = event.get("event_name", "")
        username = event.get("username", "Unknown")
        source_ip = event.get("source_ip", "Unknown")
        error_code = event.get("error_code", "")

        event_counts[event_name] += 1
        user_events[username].append(event)
        ip_events[source_ip].append(event)

        # Başarısız giriş sayısı
        if event_name == "ConsoleLogin" and error_code:
            failed_logins[source_ip] += 1

    # Saldırı pattern tespiti
    for pattern_name, pattern in ATTACK_PATTERNS.items():
        matched_events = []
        for event_name in pattern["events"]:
            if event_counts[event_name] > 0:
                matched_events.append({
                    "event": event_name,
                    "count": event_counts[event_name]
                })

        if matched_events:
            threats["attack_patterns"].append({
                "pattern": pattern_name,
                "description": pattern["description"],
                "severity": pattern["severity"],
                "matched_events": matched_events,
                "total_occurrences": sum(e["count"] for e in matched_events)
            })

            if pattern["severity"] == "CRITICAL":
                threats["risk_score"] += 30
            elif pattern["severity"] == "HIGH":
                threats["risk_score"] += 20
            elif pattern["severity"] == "MEDIUM":
                threats["risk_score"] += 10

    # Brute force tespiti
    for ip, count in failed_logins.items():
        if count >= 3:
            threats["anomalies"].append({
                "type": "BRUTE_FORCE",
                "severity": "HIGH",
                "description": f"Brute force saldırısı: {ip} — {count} başarısız giriş",
                "source_ip": ip
            })
            threats["risk_score"] += 25

    # Şüpheli IP aktivitesi
    for ip, data in ip_results.items():
        if data.get("threat_score", 0) > 30:
            ip_event_list = ip_events.get(ip, [])
            if ip_event_list:
                threats["anomalies"].append({
                    "type": "SUSPICIOUS_IP",
                    "severity": "HIGH",
                    "description": f"Şüpheli IP aktivitesi: {ip} ({', '.join(data.get('threat_types', []))})",
                    "source_ip": ip,
                    "event_count": len(ip_event_list)
                })
                threats["risk_score"] += 20

    # Gece yarısı kritik aktivite
    midnight_critical = [
        e for e in timeline_events
        if e.get("is_midnight") and e.get("severity") in ["CRITICAL", "HIGH"]
    ]
    if midnight_critical:
        threats["anomalies"].append({
            "type": "MIDNIGHT_ACTIVITY",
            "severity": "HIGH",
            "description": f"Gece yarısı {len(midnight_critical)} kritik aktivite tespit edildi",
            "events": [e["event_name"] for e in midnight_critical[:5]]
        })
        threats["risk_score"] += 15

    # Tehlikeye girmiş hesaplar
    for username, events in user_events.items():
        critical_events = [e for e in events if e.get("severity") in ["CRITICAL", "HIGH"]]
        if len(critical_events) >= 2:
            threats["compromised_accounts"].append({
                "username": username,
                "critical_actions": len(critical_events),
                "actions": list(set(e["event_name"] for e in critical_events))[:5]
            })

    threats["risk_score"] = min(100, threats["risk_score"])

    # Risk seviyesi
    if threats["risk_score"] >= 70:
        threats["risk_level"] = "CRITICAL"
        threats["risk_color"] = "red"
    elif threats["risk_score"] >= 40:
        threats["risk_level"] = "HIGH"
        threats["risk_color"] = "orange"
    elif threats["risk_score"] >= 20:
        threats["risk_level"] = "MEDIUM"
        threats["risk_color"] = "yellow"
    else:
        threats["risk_level"] = "LOW"
        threats["risk_color"] = "green"

    return threats