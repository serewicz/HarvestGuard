import sys

import boto3
import pandas as pd
from botocore.exceptions import ClientError

from finding_adapters import normalize_s3_df
from findings import NormalizedFinding

# The only head_object ClientError codes that mean "this one object is
# genuinely absent" -- a key can vanish between list_objects_v2 and
# head_object (deletion, lifecycle expiry), and S3 surfaces that as a bare
# "404" (HEAD responses carry no error body) or NoSuchKey/NotFound. Every
# other code -- AccessDenied, ExpiredToken, InvalidAccessKeyId,
# SignatureDoesNotMatch, throttling, 5xx -- is a provider/auth/execution
# failure: skipping it would silently produce an incomplete scan that the
# CLI reports as success, so it propagates instead. Unknown/missing codes
# propagate too (fail closed).
_ABSENT_OBJECT_CODES = frozenset({"404", "NoSuchKey", "NotFound"})


def _collect_s3_objects(bucket_name: str, prefix: str = "") -> pd.DataFrame:
    """List S3 objects with encryption status; raise on bucket/auth failure.

    A single genuinely-absent object (head_object 404/NoSuchKey/NotFound,
    e.g. deleted between listing and inspection) is skipped so it doesn't
    abort the whole scan. Any other head_object ClientError -- and any
    failure to list the bucket or authenticate -- propagates to the caller
    so it can be surfaced (e.g. as a nonzero CLI exit code) rather than
    silently masked as an incomplete-but-successful scan.
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
        except ClientError as exc:
            code = str(exc.response.get("Error", {}).get("Code", ""))
            if code in _ABSENT_OBJECT_CODES:
                continue
            raise

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
