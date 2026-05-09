import sys
import os
from datetime import datetime
from modules.evidence_collector import collect_cloudtrail_evidence, collect_iam_snapshot, collect_s3_evidence, save_evidence
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

def run_investigation(hours=24, all_regions=False, save_raw=True):
    banner()

    start_time = datetime.now()
    print(f"  {COLORS['WHITE']}Analiz başlangıcı: {start_time.strftime('%d.%m.%Y %H:%M:%S')}{COLORS['RESET']}")
    print(f"  {COLORS['WHITE']}Zaman aralığı: Son {hours} saat{COLORS['RESET']}")
    print(f"  {COLORS['WHITE']}Çoklu bölge: {'Evet' if all_regions else 'Hayır'}{COLORS['RESET']}\n")

    # ADIM 1: CloudTrail kanıtları
    print_step(1, 6, "CloudTrail kanıtları toplanıyor...")
    evidence = collect_cloudtrail_evidence(hours=hours, all_regions=all_regions)

    if evidence.get("error"):
        print_warning(f"CloudTrail hatası: {evidence['error']}")
    else:
        print_success(f"{evidence['total_events']} olay toplandı")
        if evidence.get("regions_scanned"):
            print_success(f"Taranan bölgeler: {', '.join(evidence['regions_scanned'])}")

    if save_raw:
        path = save_evidence(evidence, "cloudtrail_evidence.json")
        print_success(f"Kanıtlar kaydedildi: {path}")

    # ADIM 2: IAM snapshot
    print_step(2, 6, "IAM snapshot alınıyor...")
    iam_snapshot = collect_iam_snapshot()

    if iam_snapshot.get("error"):
        print_warning(f"IAM hatası: {iam_snapshot['error']}")
    else:
        print_success(f"{len(iam_snapshot['users'])} kullanıcı, {len(iam_snapshot['roles'])} rol tespit edildi")

        # Uzun süredir kullanılmayan anahtarlar
        for user in iam_snapshot["users"]:
            for key in user.get("access_keys", []):
                if key.get("age_days", 0) > 90:
                    print_warning(f"Eski erişim anahtarı: {user['username']} — {key['age_days']} gün")

        if save_raw:
            save_evidence(iam_snapshot, "iam_snapshot.json")
            print_success("IAM snapshot kaydedildi")

    # ADIM 3: S3 kanıtları
    print_step(3, 6, "S3 bucket'ları analiz ediliyor...")
    s3_evidence = collect_s3_evidence()

    if s3_evidence.get("error"):
        print_warning(f"S3 hatası: {s3_evidence['error']}")
    else:
        print_success(f"{s3_evidence['total_buckets']} bucket tespit edildi")
        if s3_evidence["public_buckets"]:
            for bucket in s3_evidence["public_buckets"]:
                print_critical(f"Public bucket: {bucket}")
        else:
            print_success("Public bucket bulunamadı")

        if save_raw:
            save_evidence(s3_evidence, "s3_evidence.json")

    # ADIM 4: Zaman çizelgesi
    print_step(4, 6, "Zaman çizelgesi oluşturuluyor...")
    timeline = build_timeline(evidence.get("events", []))
    print_success(f"Zaman çizelgesi: {timeline['summary']['total']} olay")
    print_success(f"Şüpheli: {timeline['summary']['critical']} kritik, {timeline['summary']['high']} yüksek")

    # ADIM 5: IP araştırma
    print_step(5, 6, "IP adresleri araştırılıyor...")
    unique_ips = list(set(
        e.get("source_ip", "") for e in evidence.get("events", [])
        if e.get("source_ip", "") and e.get("source_ip") != "Unknown"
    ))

    ip_results = investigate_multiple_ips(unique_ips[:20])
    suspicious_ips = get_suspicious_ips(ip_results)

    if suspicious_ips:
        for ip_info in suspicious_ips:
            print_warning(f"Şüpheli IP: {ip_info['ip']} — {', '.join(ip_info['threat_types'])}")
    else:
        print_success("Şüpheli IP tespit edilmedi")

    # ADIM 6: Tehdit analizi ve rapor
    print_step(6, 6, "Tehdit analizi ve rapor oluşturuluyor...")
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

    report_path = generate_forensics_report(evidence, timeline, ip_results, threats)
    print_success(f"PDF rapor: {report_path}")

    # Zaman çizelgesini yazdır
    print_timeline(timeline)

    # Özet
    end_time = datetime.now()
    duration = (end_time - start_time).seconds

    print(f"\n{COLORS['CYAN']}{'═' * 60}{COLORS['RESET']}")
    print(f"{COLORS['WHITE']}  Analiz tamamlandı — {duration} saniye{COLORS['RESET']}")
    print(f"{COLORS['WHITE']}  Bölgeler: {', '.join(evidence.get('regions_scanned', ['eu-central-1']))}{COLORS['RESET']}")
    print(f"{COLORS['WHITE']}  Rapor: reports/forensics_report.pdf{COLORS['RESET']}")
    print(f"{COLORS['CYAN']}{'═' * 60}{COLORS['RESET']}\n")

    return {
        "evidence": evidence,
        "iam_snapshot": iam_snapshot,
        "s3_evidence": s3_evidence,
        "timeline": timeline,
        "ip_results": ip_results,
        "threats": threats,
        "report_path": report_path
    }

if __name__ == "__main__":
    hours = 24
    all_regions = False

    if len(sys.argv) > 1:
        try:
            hours = int(sys.argv[1])
        except:
            pass

    if "--all-regions" in sys.argv:
        all_regions = True
        print(f"  {COLORS['YELLOW']}⚠ Tüm bölgeler taranacak — bu biraz uzun sürebilir{COLORS['RESET']}")

    run_investigation(hours=hours, all_regions=all_regions)