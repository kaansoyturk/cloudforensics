import boto3
import json
import os
from datetime import datetime, timezone, timedelta
from dotenv import load_dotenv

load_dotenv()

AWS_ACCESS_KEY = os.getenv("AWS_ACCESS_KEY_ID")
AWS_SECRET_KEY = os.getenv("AWS_SECRET_ACCESS_KEY")
AWS_REGION = os.getenv("AWS_REGION", "eu-central-1")

ALL_REGIONS = [
    "us-east-1", "us-east-2", "us-west-1", "us-west-2",
    "eu-west-1", "eu-west-2", "eu-central-1", "eu-north-1",
    "ap-southeast-1", "ap-southeast-2", "ap-northeast-1",
    "sa-east-1", "ca-central-1"
]

def collect_cloudtrail_evidence(hours=24, all_regions=False):
    """CloudTrail'den kanıt topla"""
    evidence = {
        "collection_time": datetime.now(timezone.utc).isoformat(),
        "time_range_hours": hours,
        "events": [],
        "total_events": 0,
        "regions_scanned": [],
        "error": None
    }

    regions = ALL_REGIONS if all_regions else [AWS_REGION]

    for region in regions:
        try:
            ct = boto3.client(
                "cloudtrail",
                aws_access_key_id=AWS_ACCESS_KEY,
                aws_secret_access_key=AWS_SECRET_KEY,
                region_name=region
            )

            start_time = datetime.now(timezone.utc) - timedelta(hours=hours)

            paginator = ct.get_paginator("lookup_events")
            pages = paginator.paginate(
                StartTime=start_time,
                EndTime=datetime.now(timezone.utc),
                PaginationConfig={"MaxItems": 200, "PageSize": 50}
            )

            region_events = 0
            for page in pages:
                for event in page.get("Events", []):
                    event_detail = {}
                    if event.get("CloudTrailEvent"):
                        try:
                            event_detail = json.loads(event["CloudTrailEvent"])
                        except:
                            pass

                    evidence["events"].append({
                        "event_id": event.get("EventId", ""),
                        "event_name": event.get("EventName", ""),
                        "event_time": event.get("EventTime", datetime.now(timezone.utc)).isoformat(),
                        "username": event.get("Username", "Unknown"),
                        "source_ip": event_detail.get("sourceIPAddress", ""),
                        "user_agent": event_detail.get("userAgent", ""),
                        "region": region,
                        "error_code": event_detail.get("errorCode", ""),
                        "error_message": event_detail.get("errorMessage", ""),
                        "request_parameters": event_detail.get("requestParameters", {}),
                        "response_elements": event_detail.get("responseElements", {}),
                        "resources": event.get("Resources", [])
                    })
                    region_events += 1

            if region_events > 0:
                evidence["regions_scanned"].append(f"{region} ({region_events} olay)")
                print(f"    ✓ {region}: {region_events} olay")

        except Exception as e:
            if "AccessDenied" not in str(e) and "UnrecognizedClientException" not in str(e):
                print(f"    ⚠ {region}: {str(e)[:50]}")

    evidence["total_events"] = len(evidence["events"])
    return evidence


def collect_iam_snapshot():
    """IAM durumunu kaydet"""
    snapshot = {
        "collection_time": datetime.now(timezone.utc).isoformat(),
        "users": [],
        "roles": [],
        "recent_changes": [],
        "error": None
    }

    try:
        iam = boto3.client(
            "iam",
            aws_access_key_id=AWS_ACCESS_KEY,
            aws_secret_access_key=AWS_SECRET_KEY,
            region_name=AWS_REGION
        )

        # Kullanıcılar
        users = iam.list_users()["Users"]
        for user in users:
            user_info = {
                "username": user["UserName"],
                "created": user["CreateDate"].isoformat(),
                "last_used": str(user.get("PasswordLastUsed", "Never")),
                "access_keys": [],
                "groups": [],
                "policies": []
            }

            # Erişim anahtarları
            keys = iam.list_access_keys(UserName=user["UserName"])
            for key in keys["AccessKeyMetadata"]:
                age_days = (datetime.now(timezone.utc) - key["CreateDate"]).days
                user_info["access_keys"].append({
                    "key_id": key["AccessKeyId"][:8] + "...",
                    "status": key["Status"],
                    "created": key["CreateDate"].isoformat(),
                    "age_days": age_days
                })

            # Gruplar
            groups = iam.list_groups_for_user(UserName=user["UserName"])
            user_info["groups"] = [g["GroupName"] for g in groups["Groups"]]

            # Politikalar
            policies = iam.list_attached_user_policies(UserName=user["UserName"])
            user_info["policies"] = [p["PolicyName"] for p in policies["AttachedPolicies"]]

            snapshot["users"].append(user_info)

        # Roller
        roles = iam.list_roles()["Roles"]
        for role in roles:
            if not role["RoleName"].startswith("AWS"):
                snapshot["roles"].append({
                    "name": role["RoleName"],
                    "created": role["CreateDate"].isoformat(),
                    "description": role.get("Description", "")
                })

    except Exception as e:
        snapshot["error"] = str(e)

    return snapshot


def collect_s3_evidence():
    """S3 bucket bilgilerini topla"""
    s3_evidence = {
        "collection_time": datetime.now(timezone.utc).isoformat(),
        "buckets": [],
        "total_buckets": 0,
        "public_buckets": [],
        "error": None
    }

    try:
        s3 = boto3.client(
            "s3",
            aws_access_key_id=AWS_ACCESS_KEY,
            aws_secret_access_key=AWS_SECRET_KEY,
            region_name=AWS_REGION
        )

        buckets = s3.list_buckets().get("Buckets", [])
        s3_evidence["total_buckets"] = len(buckets)

        for bucket in buckets:
            name = bucket["Name"]
            bucket_info = {
                "name": name,
                "created": bucket["CreationDate"].isoformat(),
                "public": False,
                "encryption": False,
                "versioning": False,
                "logging": False
            }

            # Public kontrolü
            try:
                public = s3.get_public_access_block(Bucket=name)
                config = public["PublicAccessBlockConfiguration"]
                bucket_info["public"] = not all([
                    config.get("BlockPublicAcls", False),
                    config.get("BlockPublicPolicy", False),
                    config.get("RestrictPublicBuckets", False),
                    config.get("IgnorePublicAcls", False)
                ])
                if bucket_info["public"]:
                    s3_evidence["public_buckets"].append(name)
            except:
                pass

            # Şifreleme kontrolü
            try:
                s3.get_bucket_encryption(Bucket=name)
                bucket_info["encryption"] = True
            except:
                pass

            # Versioning kontrolü
            try:
                ver = s3.get_bucket_versioning(Bucket=name)
                bucket_info["versioning"] = ver.get("Status") == "Enabled"
            except:
                pass

            s3_evidence["buckets"].append(bucket_info)

    except Exception as e:
        s3_evidence["error"] = str(e)

    return s3_evidence


def save_evidence(evidence, filename):
    """Kanıtları dosyaya kaydet"""
    os.makedirs("reports", exist_ok=True)
    filepath = f"reports/{filename}"
    with open(filepath, "w") as f:
        json.dump(evidence, f, indent=2, default=str)
    return filepath