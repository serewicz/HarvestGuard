import boto3
import pandas as pd
from botocore.exceptions import ClientError

from finding_adapters import normalize_s3_df
from findings import NormalizedFinding
from scanner.errors import CloudScanError


def scan_s3_bucket(bucket_name: str, prefix: str = "", errors: list[str] | None = None):
    """Scan S3 bucket for encryption status.

    A scan-level failure (auth/provider error) is swallowed so the Streamlit
    dashboard degrades to an empty result. A per-object ``head_object`` failure
    (for example AccessDenied on a single key) is also recorded, because it is a
    coverage gap: the object's encryption status is unknown and its finding is
    missing, so an empty or partial result would otherwise look like a clean
    scan. When ``errors`` is provided, failures are recorded there instead of
    printed, so a caller (the CLI) can distinguish a failed or incomplete scan
    from an empty bucket and report it explicitly.
    """
    s3 = boto3.client('s3')
    results = []

    def _record(message: str) -> None:
        if errors is None:
            print(message)
        else:
            errors.append(message)

    try:
        # list_objects_v2 returns at most 1,000 keys per call, so iterate every
        # page. Without this a large bucket is silently reported as complete
        # after only its first page, hiding all later objects from the scan.
        continuation_token: str | None = None
        while True:
            kwargs = {"Bucket": bucket_name, "Prefix": prefix}
            if continuation_token is not None:
                kwargs["ContinuationToken"] = continuation_token
            response = s3.list_objects_v2(**kwargs)
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
                except ClientError as e:
                    _record(f"Error reading encryption status for s3://{bucket_name}/{key}: {e}")
            if not response.get('IsTruncated'):
                break
            continuation_token = response.get('NextContinuationToken')
            if not continuation_token:
                break
    except Exception as e:
        _record(f"Error scanning S3: {e}")

    return pd.DataFrame(results)


def scan_s3_bucket_findings(
    bucket_name: str, prefix: str = "", scan_id: str | None = None
) -> list[NormalizedFinding]:
    errors: list[str] = []
    df = scan_s3_bucket(bucket_name, prefix=prefix, errors=errors)
    if errors:
        raise CloudScanError("; ".join(errors))
    return normalize_s3_df(df, scan_id=scan_id)
