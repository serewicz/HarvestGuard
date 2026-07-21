import boto3
import pandas as pd
from botocore.exceptions import ClientError

from finding_adapters import normalize_s3_df
from findings import NormalizedFinding


def scan_s3_bucket(bucket_name: str, prefix: str = ""):
    """Scan S3 bucket for encryption status."""
    s3 = boto3.client('s3')
    results = []

    try:
        response = s3.list_objects_v2(Bucket=bucket_name, Prefix=prefix)
        for obj in response.get('Contents', []):
            key = obj['Key']
            try:
                enc = s3.head_object(Bucket=bucket_name, Key=key)
                enc_status = enc.get('ServerSideEncryption', 'None')
                results.append({
                    "Location": f"s3://{bucket_name}/{key}",
                    "Size": obj['Size'],
                    "Modified": obj['LastModified'],
                    "Encryption": enc_status,
                    "Risk": "Low" if enc_status != "None" else "High"
                })
            except ClientError:
                pass
    except Exception as e:
        print(f"Error scanning S3: {e}")

    return pd.DataFrame(results)


def scan_s3_bucket_findings(
    bucket_name: str, prefix: str = "", scan_id: str | None = None
) -> list[NormalizedFinding]:
    return normalize_s3_df(scan_s3_bucket(bucket_name, prefix=prefix), scan_id=scan_id)
