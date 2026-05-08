import sys
import os
from datetime import datetime
from modules.evidence_collector import collect_cloudtrail_evidence, collect_iam_snapshot, save_evidence
from modules.timeline_builder import build_timeline, print_timeline
from modules.ip_investigator import investigate_multiple_ips, get_suspicious_ips
from modules.threat_analyzer import analyze_threats
from modules.report_generator import generate_forensics_report

COLORS = {
    "RED": "\033[91m",
    "GREEN": "\033[92m",
    "YELLOW": "\033[93m",
    "BLUE": "\033[94m",
    "CYAN": "\033[96m",
    "WHITE": "\033[97m",
    "RESET": "\033[0m",
    "BOLD": "\033[1m"
}

def banner():
    c = COLORS
    print(f"""
{c['CYAN']}{c['BOLD']}
  ██████╗██╗      ██████╗ ██╗   ██╗██████╗
 ██╔════╝██║     ██╔═══██╗██║   ██║██╔══██╗
 ██║     ██║     ██║   ██║██║   ██║██║  ██║
 ██║     ██║     ██║   ██║██║   ██║██║  ██║
 ╚██████╗███████╗╚██████╔╝╚██████╔╝██████╔╝
  ╚═════╝╚══════╝ ╚═════╝  ╚═════╝ ╚═════╝
{c['RESET']}
{c['WHITE']}  CloudForensics — AWS Dijital Adli Analiz Araci{c['RESET']}
{c['CYAN']}  github.com/kaansoyturk{c['RESET']}
""")

def print_step(step, total, message):
    c = COLORS
    print(f"\n{c['CYAN']}[{step}/{total}] {message}{c['RESET']}")
    print(f"  {'─' * 50}")

def print_success(message):
    print(f"  {COLORS['GREEN']}✓ {message}{COLORS['RESET']}")

def print_warning(message):
    print(f"  {COLORS['YELLOW']}⚠ {message}{COLORS['RESET']}")

def print_critical(message):
    print(f"  {COLORS['RED']}🚨 {message}{COLORS['RESET']}")

def run_investigation(hours=24, save_raw=True):
    banner()

    start_time = datetime.now()
    print(f"  {COLORS['WHITE']}Analiz başlangıcı: {start_time.strftime('%d.%m.%Y %H:%M:%S')}{COLORS['RESET']}")
    print(f"  {COLORS['WHITE']}Zaman aralığı: Son {hours} saat{COLORS['RESET']}\n")

    # ADIM 1: Kanıt toplama
    print_step(1, 5, "CloudTrail kanıtları toplanıyor...")
    evidence = collect_cloudtrail_evidence(hours=hours)

    if evidence.get("error"):
        print_warning(f"CloudTrail hatası: {evidence['error']}")
    else:
        print_success(f"{evidence['total_events']} olay toplandı")

    if save_raw:
        path = save_evidence(evidence, "cloudtrail_evidence.json")
        print_success(f"Kanıtlar kaydedildi: {path}")

    # ADIM 2: Zaman çizelgesi
    print_step(2, 5, "Zaman çizelgesi oluşturuluyor...")
    timeline = build_timeline(evidence.get("events", []))
    print_success(f"Zaman çizelgesi oluşturuldu: {timeline['summary']['total']} olay")
    print_success(f"Şüpheli olaylar: {timeline['summary']['critical']} kritik, {timeline['summary']['high']} yüksek")

    # ADIM 3: IP araştırma
    print_step(3, 5, "IP adresleri araştırılıyor...")
    unique_ips = list(set(
        e.get("source_ip", "") for e in evidence.get("events", [])
        if e.get("source_ip", "") and e.get("source_ip") != "Unknown"
    ))

    ip_results = investigate_multiple_ips(unique_ips[:20])  # Max 20 IP
    suspicious_ips = get_suspicious_ips(ip_results)

    if suspicious_ips:
        for ip_info in suspicious_ips:
            print_warning(f"Şüpheli IP: {ip_info['ip']} — {', '.join(ip_info['threat_types'])}")
    else:
        print_success("Şüpheli IP tespit edilmedi")

    # ADIM 4: Tehdit analizi
    print_step(4, 5, "Tehdit analizi yapılıyor...")
    threats = analyze_threats(timeline["events"], ip_results)

    risk_color = COLORS["RED"] if threats["risk_level"] in ["CRITICAL", "HIGH"] else COLORS["YELLOW"]
    print(f"  {risk_color}Risk Skoru: {threats['risk_score']}/100 — {threats['risk_level']}{COLORS['RESET']}")

    for pattern in threats["attack_patterns"]:
        if pattern["severity"] in ["CRITICAL", "HIGH"]:
            print_critical(f"Saldırı Pattern: {pattern['description']}")

    for anomaly in threats["anomalies"]:
        print_warning(anomaly["description"])

    if threats["compromised_accounts"]:
        for account in threats["compromised_accounts"]:
            print_critical(f"Tehlikeye girmiş hesap: {account['username']}")

    # ADIM 5: Rapor oluşturma
    print_step(5, 5, "Forensics raporu oluşturuluyor...")
    report_path = generate_forensics_report(
        evidence, timeline, ip_results, threats
    )
    print_success(f"PDF rapor: {report_path}")

    # Zaman çizelgesini yazdır
    print_timeline(timeline)

    # Özet
    end_time = datetime.now()
    duration = (end_time - start_time).seconds

    print(f"\n{COLORS['CYAN']}{'═' * 60}{COLORS['RESET']}")
    print(f"{COLORS['WHITE']}  Analiz tamamlandı — {duration} saniye{COLORS['RESET']}")
    print(f"{COLORS['WHITE']}  Rapor: reports/forensics_report.pdf{COLORS['RESET']}")
    print(f"{COLORS['CYAN']}{'═' * 60}{COLORS['RESET']}\n")

    return {
        "evidence": evidence,
        "timeline": timeline,
        "ip_results": ip_results,
        "threats": threats,
        "report_path": report_path
    }

if __name__ == "__main__":
    hours = 24
    if len(sys.argv) > 1:
        try:
            hours = int(sys.argv[1])
        except:
            pass

    run_investigation(hours=hours)