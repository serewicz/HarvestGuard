# Read-only scan role templates

Least-privilege credentials for running HarvestGuard's cloud scanners. Each
template grants exactly the API calls the corresponding scanner module makes
— nothing else. Verify against the source if these drift; the mapping is:

| Cloud | Template | Scanner | Calls made |
|---|---|---|---|
| AWS | `aws-readonly-scan-policy.json` | `scanner/cloud.py` | `s3:ListBucket` (`list_objects_v2`), `s3:GetObject` (`head_object` — HeadObject is authorized by the `GetObject` permission, there's no separate `HeadObject` action) |
| GCP | `gcp-readonly-scan-role.yaml` | `scanner/gcs.py` | `storage.objects.list`, `storage.objects.get` (`list_blobs`) |
| Azure | `azure-readonly-scan-role.json` | `scanner/azure_blob.py` | `.../blobs/read` (`list_blobs`) |

## Usage

**AWS** — replace `REPLACE_WITH_BUCKET_NAME`, then:
```bash
aws iam create-policy --policy-name HarvestGuardReadOnlyScan \
  --policy-document file://aws-readonly-scan-policy.json
```

**GCP**:
```bash
gcloud iam roles create harvestGuardReadOnlyScan --project=YOUR_PROJECT \
  --file=gcp-readonly-scan-role.yaml
```

**Azure** — the built-in **Storage Blob Data Reader** role already grants
exactly the permission HarvestGuard needs. Prefer assigning that directly:
```bash
az role assignment create --role "Storage Blob Data Reader" \
  --assignee <principal-id> --scope <storage-account-or-container-resource-id>
```
`azure-readonly-scan-role.json` (replace `REPLACE_WITH_SUBSCRIPTION_ID`) is
provided only for environments where policy requires a custom role
definition instead of a built-in one.

None of these grant write, delete, or configuration-change permissions —
HarvestGuard only ever lists and reads.
