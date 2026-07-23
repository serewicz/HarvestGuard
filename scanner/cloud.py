import sys

import boto3
import pandas as pd
from botocore.exceptions import ClientError

from finding_adapters import normalize_s3_df
from findings import NormalizedFinding


def _collect_s3_objects(bucket_name: str, prefix: str = "") -> pd.DataFrame:
    """List S3 objects with encryption status; raise on bucket/auth failure.

    A single unreadable object (head_object ClientError) is skipped so it
    doesn't abort the whole scan, but a failure to list the bucket -- or an
    auth/credentials failure -- propagates to the caller so it can be surfaced
    (e.g. as a nonzero CLI exit code) rather than silently masked.
    """
    s3 = boto3.client('s3')
    results = []

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

    return pd.DataFrame(results)


def scan_s3_bucket(bucket_name: str, prefix: str = ""):
    """Scan S3 bucket for encryption status (DataFrame view for the dashboard).

    Swallows scan failures and returns an empty DataFrame so the Streamlit app
    keeps working. The error goes to stderr, never stdout, so machine-readable
    output on stdout is not corrupted. The CLI uses scan_s3_bucket_findings,
    which propagates the failure so it can be surfaced as a nonzero exit code.
    """
    try:
        return _collect_s3_objects(bucket_name, prefix=prefix)
    except Exception as e:
        print(f"Error scanning S3: {e}", file=sys.stderr)
        return pd.DataFrame([])


def scan_s3_bucket_findings(
    bucket_name: str, prefix: str = "", scan_id: str | None = None
) -> list[NormalizedFinding]:
    return normalize_s3_df(_collect_s3_objects(bucket_name, prefix=prefix), scan_id=scan_id)
