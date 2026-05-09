# 🔬 CloudForensics

AWS ortamlarında güvenlik ihlali sonrası dijital adli analiz aracı.

## Ne Yapıyor?

Bir güvenlik ihlali sonrası AWS CloudTrail loglarını toplayıp analiz eder, saldırı kalıplarını tespit eder, şüpheli IP'leri araştırır ve profesyonel forensics raporu üretir.

## Modüller

- Evidence Collector — CloudTrail, IAM snapshot ve S3 bucket analizi
- Timeline Builder — Olayları zamana göre sıralama ve şüpheli aktivite tespiti
- IP Investigator — Kaynak IP'leri araştırma, VPN/Proxy/Datacenter tespiti
- Threat Analyzer — MITRE ATT&CK saldırı pattern tespiti, brute force, gece yarısı aktivite
- Report Generator — Profesyonel PDF forensics raporu

## Özellikler

- 13 AWS bölgesini tek seferde tarama
- CloudTrail log analizi
- IAM kullanıcı ve rol snapshot
- S3 bucket güvenlik analizi
- IP threat intelligence
- MITRE ATT&CK pattern eşleştirme
- Brute force ve gece yarısı aktivite tespiti
- Profesyonel PDF rapor

## Tespit Edilen Tehditler

- Defense Evasion (CloudTrail silme, logging durdurma)
- Persistence (yeni kullanıcı, erişim anahtarı oluşturma)
- Credential Access (secret okuma, oturum alma)
- Exfiltration (S3 veri sızdırma)
- Impact (bucket ve veritabanı silme)
- Brute Force saldırıları
- Gece yarısı kritik aktiviteler
- Şüpheli IP aktiviteleri (VPN, Proxy, Tor, Datacenter)

## Teknolojiler

- Python 3
- boto3 — AWS CloudTrail, IAM, S3 API
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

Son 24 saat (tek bölge):

    python3 main.py

Son 7 gun (tek bölge):

    python3 main.py 168

Son 7 gun (tum bölgeler):

    python3 main.py 168 --all-regions

Son 30 gun:

    python3 main.py 720

## Ornek Cikti

    [1/6] CloudTrail kanıtları toplanıyor...
      ✓ us-east-1: 200 olay
      ✓ eu-central-1: 39 olay
      ✓ 439 olay toplandı

    [2/6] IAM snapshot alınıyor...
      ✓ 1 kullanıcı, 0 rol tespit edildi

    [3/6] S3 bucket'ları analiz ediliyor...
      ✓ 0 bucket tespit edildi

    [4/6] Zaman çizelgesi oluşturuluyor...
      ✓ Şüpheli: 0 kritik, 7 yüksek

    [5/6] IP adresleri araştırılıyor...
      ⚠ Şüpheli IP: 185.220.101.45 — Tor Exit Node

    [6/6] Tehdit analizi ve rapor oluşturuluyor...
      🚨 Risk Skoru: 75/100 — HIGH
      🚨 Saldırı Pattern: Defense Evasion
      🚨 Tehlikeye girmiş hesap: root

## Gelistirici

Kaan Soyturk — github.com/kaansoyturk