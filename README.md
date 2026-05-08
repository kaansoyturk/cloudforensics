# 🔬 CloudForensics

AWS ortamlarında güvenlik ihlali sonrası dijital adli analiz aracı.

## Ne Yapıyor?

Bir güvenlik ihlali sonrası AWS CloudTrail loglarını toplayıp analiz eder, saldırı kalıplarını tespit eder, şüpheli IP'leri araştırır ve profesyonel forensics raporu üretir.

## Modüller

- Evidence Collector — CloudTrail ve IAM snapshot toplama
- Timeline Builder — Olayları zamana göre sıralama ve şüpheli aktivite tespiti
- IP Investigator — Kaynak IP'leri araştırma, VPN/Proxy/Datacenter tespiti
- Threat Analyzer — MITRE ATT&CK saldırı pattern tespiti, brute force, gece yarısı aktivite
- Report Generator — Profesyonel PDF forensics raporu

## Tespit Edilen Tehditler

- Defense Evasion (CloudTrail silme, logging durdurma)
- Persistence (yeni kullanıcı, erişim anahtarı oluşturma)
- Credential Access (secret okuma, oturum alma)
- Exfiltration (S3 veri sızdırma)
- Impact (bucket ve veritabanı silme)
- Brute Force saldırıları
- Gece yarısı kritik aktiviteler
- Şüpheli IP aktiviteleri (VPN, Proxy, Tor)

## Teknolojiler

- Python 3
- boto3 — AWS CloudTrail API
- reportlab — PDF rapor
- requests — IP araştırma
- colorama — Renkli terminal

## Kurulum

    git clone https://github.com/kaansoyturk/cloudforensics.git
    cd cloudforensics
    python3 -m venv venv
    source venv/bin/activate
    pip3 install boto3 colorama reportlab python-dotenv requests rich

## Yapılandırma

.env dosyası oluştur:

    AWS_ACCESS_KEY_ID=access_key_id
    AWS_SECRET_ACCESS_KEY=secret_access_key
    AWS_REGION=eu-central-1

## Kullanim

Son 24 saat:

    python3 main.py

Son 7 gun:

    python3 main.py 168

Son 30 gun:

    python3 main.py 720

## Ornek Cikti

    [1/5] CloudTrail kanıtları toplanıyor...
      ✓ 25 olay toplandı

    [2/5] Zaman çizelgesi oluşturuluyor...
      ✓ Şüpheli olaylar: 3 kritik, 7 yüksek

    [3/5] IP adresleri araştırılıyor...
      ⚠ Şüpheli IP: 185.220.101.45 — Tor Exit Node

    [4/5] Tehdit analizi yapılıyor...
      🚨 Risk Skoru: 75/100 — HIGH
      🚨 Saldırı Pattern: Defense Evasion

    [5/5] Forensics raporu oluşturuluyor...
      ✓ PDF rapor: reports/forensics_report.pdf

## Gelistirici

Kaan Soyturk — github.com/kaansoyturk