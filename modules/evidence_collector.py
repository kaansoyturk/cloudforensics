import boto3
import json
import os
from datetime import datetime, timezone, timedelta
from dotenv import load_dotenv

load_dotenv()

AWS_ACCESS_KEY = os.getenv("AWS_ACCESS_KEY_ID")
AWS_SECRET_KEY = os.getenv("AWS_SECRET_ACCESS_KEY")
AWS_REGION = os.getenv("AWS_REGION", "eu-central-1")


def collect_cloudtrail_evidence(hours=24):
    """CloudTrail'den kanıt topla"""
    evidence = {
        "collection_time": datetime.now(timezone.utc).isoformat(),
        "time_range_hours": hours,
        "events": [],
        "total_events": 0,
        "error": None
    }

    try:
        ct = boto3.client(
            "cloudtrail",
            aws_access_key_id=AWS_ACCESS_KEY,
            aws_secret_access_key=AWS_SECRET_KEY,
            region_name=AWS_REGION
        )

        start_time = datetime.now(timezone.utc) - timedelta(hours=hours)

        paginator = ct.get_paginator("lookup_events")
        pages = paginator.paginate(
            StartTime=start_time,
            EndTime=datetime.now(timezone.utc),
            PaginationConfig={"MaxItems": 500, "PageSize": 50}
        )

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
                    "region": event_detail.get("awsRegion", AWS_REGION),
                    "error_code": event_detail.get("errorCode", ""),
                    "error_message": event_detail.get("errorMessage", ""),
                    "request_parameters": event_detail.get("requestParameters", {}),
                    "response_elements": event_detail.get("responseElements", {}),
                    "resources": event.get("Resources", [])
                })

        evidence["total_events"] = len(evidence["events"])

    except Exception as e:
        evidence["error"] = str(e)

    return evidence


def collect_iam_snapshot():
    """IAM durumunu kaydet"""
    snapshot = {
        "collection_time": datetime.now(timezone.utc).isoformat(),
        "users": [],
        "roles": [],
        "policies": [],
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
                "last_used": user.get("PasswordLastUsed", "Never"),
                "access_keys": []
            }

            # Erişim anahtarları
            keys = iam.list_access_keys(UserName=user["UserName"])
            for key in keys["AccessKeyMetadata"]:
                user_info["access_keys"].append({
                    "key_id": key["AccessKeyId"],
                    "status": key["Status"],
                    "created": key["CreateDate"].isoformat()
                })

            snapshot["users"].append(user_info)

    except Exception as e:
        snapshot["error"] = str(e)

    return snapshot


def save_evidence(evidence, filename):
    """Kanıtları dosyaya kaydet"""
    os.makedirs("reports", exist_ok=True)
    filepath = f"reports/{filename}"
    with open(filepath, "w") as f:
        json.dump(evidence, f, indent=2, default=str)
    return filepath