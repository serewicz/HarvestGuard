import boto3
import pandas as pd
from botocore.exceptions import ClientError

from finding_adapters import normalize_s3_df
from findings import NormalizedFinding
from scanner.errors import CloudScanError


def scan_s3_bucket(bucket_name: str, prefix: str = "", errors: list[str] | None = None):
    """Scan S3 bucket for encryption status.

    A scan-level failure (auth/provider error) is swallowed so the Streamlit
    dashboard degrades to an empty result. When ``errors`` is provided, the
    failure is recorded there instead of printed, so a caller (the CLI) can
    distinguish a failed scan from an empty bucket and report it explicitly.
    """
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
        message = f"Error scanning S3: {e}"
        if errors is None:
            print(message)
        else:
            errors.append(message)

    return pd.DataFrame(results)


def scan_s3_bucket_findings(
    bucket_name: str, prefix: str = "", scan_id: str | None = None
) -> list[NormalizedFinding]:
    errors: list[str] = []
    df = scan_s3_bucket(bucket_name, prefix=prefix, errors=errors)
    if errors:
        raise CloudScanError("; ".join(errors))
    return normalize_s3_df(df, scan_id=scan_id)
