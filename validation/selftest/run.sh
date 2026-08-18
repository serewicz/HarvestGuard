#!/usr/bin/env bash

set -euo pipefail

SELFTEST_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=../lib/common.sh
. "$SELFTEST_ROOT/lib/common.sh"

SELFTEST_TMP="$(mktemp -d "${TMPDIR:-/tmp}/hg-validation-selftest.XXXXXX")"
trap 'rm -rf -- "$SELFTEST_TMP"' EXIT

pass() { printf 'ok - %s\n' "$1"; }
fail() { printf 'not ok - %s\n' "$1" >&2; exit 1; }

gate_workspace="$SELFTEST_TMP/gate"
mkdir -p "$gate_workspace"
gate_script=". '$SELFTEST_ROOT/lib/common.sh'; . '$SELFTEST_ROOT/lib/gates.sh'; HG_WORKSPACE='$gate_workspace'; HG_NON_INTERACTIVE=0; HG_GATE_STDIN_ONLY=1; hg_gate_reset; hg_gate 1 test"
gate_output="$(printf '\ncontinue\n' | bash -c "$gate_script" 2>&1)" || fail "gate continuation"
printf '%s' "$gate_output" | grep -q "gate remains closed" || fail "empty gate input rejection"
printf '%s' "$gate_output" | grep -q "Confirmed. Continuing" || fail "explicit continue"
pass "gate continuation requires explicit continue"

set +e
printf 'abort\n' | bash -c "$gate_script" >/dev/null 2>&1
abort_status=$?
set -e
[ "$abort_status" -eq 10 ] || fail "abort status"
[ -d "$gate_workspace" ] || fail "abort workspace preservation"
pass "abort leaves workspace intact"

mkdir -p "$SELFTEST_TMP/guard/inside"
HG_WORKSPACE="$(cd "$SELFTEST_TMP/guard" && pwd -P)"
export HG_WORKSPACE
hg_assert_within_workspace "$HG_WORKSPACE/inside"
set +e
(hg_assert_within_workspace "$SELFTEST_TMP/outside") >/dev/null 2>&1
guard_status=$?
set -e
[ "$guard_status" -ne 0 ] || fail "workspace guard"
pass "workspace guard rejects outside paths"

redacted="$(hg_redact_command "tool --password hunter2 --token=abc -passout pass:secret")"
case "$redacted" in *hunter2* | *abc* | *pass:secret*) fail "command redaction" ;; esac
printf '%s' "$redacted" | grep -q '\[REDACTED\]' || fail "redaction marker"
pass "secret command arguments are redacted"

fixture="$SELFTEST_TMP/freeze"
mkdir -p "$fixture/corpus/operator-supplied" "$fixture/state" "$fixture/results"
printf 'blind bytes\n' > "$fixture/corpus/operator-supplied/blind.bin"
cat > "$fixture/state/artifacts.jsonl" <<'EOF'
{"artifact_id":"blind-one","source_category":"blind","relative_path":"operator-supplied/blind.bin","generator":"","generator_tool":"operator-supplied","generator_tool_version":"n/a","command_description":"operator supplied","expected_asset_type":"","expected_rule_id":"","expected_finding_count":0,"forbidden_rule_ids":[],"forbidden_asset_types":[],"additional_expected":[],"expected_scanner_error":false,"negative_control":false,"notes":"blind"}
EOF
: > "$fixture/state/skipped.tsv"
python3 "$SELFTEST_ROOT/harness_tool.py" freeze \
    --corpus-root "$fixture/corpus" --records "$fixture/state/artifacts.jsonl" \
    --out "$fixture/state/manifest.json" --run-id selftest --skipped "$fixture/state/skipped.tsv" \
    --scan-command "harvestguard scan <frozen-corpus>" >/dev/null
set +e
python3 "$SELFTEST_ROOT/harness_tool.py" freeze \
    --corpus-root "$fixture/corpus" --records "$fixture/state/artifacts.jsonl" \
    --out "$fixture/state/manifest.json" --run-id selftest >/dev/null 2>&1
freeze_status=$?
set -e
[ "$freeze_status" -ne 0 ] || fail "manifest overwrite refusal"
pass "manifest freeze refuses expectation mutation"

manifest_hash_before="$(hg_sha256 "$fixture/state/manifest.json")"
printf '[]\n' > "$fixture/results/findings.json"
printf 'selftest\n' > "$fixture/results/console.txt"
python3 "$SELFTEST_ROOT/harness_tool.py" compare \
    --manifest "$fixture/state/manifest.json" --findings "$fixture/results/findings.json" \
    --console "$fixture/results/console.txt" --out-json "$fixture/results/report.json" \
    --out-markdown "$fixture/results/report.md" --non-interactive >/dev/null
manifest_hash_after="$(hg_sha256 "$fixture/state/manifest.json")"
[ "$manifest_hash_before" = "$manifest_hash_after" ] || fail "comparison manifest mutation"
python3 - "$fixture/results/report.json" <<'PY'
import json
import pathlib
import sys

report = json.loads(pathlib.Path(sys.argv[1]).read_text())
blind = [item for item in report["results"] if item["category"] == "blind_file_observation"]
assert len(blind) == 1
assert blind[0]["validation_class"] == "blind_observation"
assert report["discrepancy_count"] == 0
PY
pass "comparison preserves manifest and does not score blind files"

HG_WORKSPACE="$SELFTEST_TMP/cleanup"
export HG_WORKSPACE
mkdir -p "$HG_WORKSPACE"
: > "$HG_WORKSPACE/.harvestguard-validation-workspace"
hg_apply_cleanup_choice "" >/dev/null 2>&1
[ -d "$HG_WORKSPACE" ] || fail "implicit cleanup"
hg_apply_cleanup_choice delete >/dev/null
[ ! -e "$HG_WORKSPACE" ] || fail "explicit cleanup"
pass "cleanup requires explicit confirmation"

dry_workspace="$SELFTEST_TMP/dry-run"
"$SELFTEST_ROOT/run-validation.sh" --dry-run --workspace "$dry_workspace" >/dev/null
[ -f "$dry_workspace/state/manifest.json" ] || fail "dry-run manifest"
[ -f "$dry_workspace/results/validation-report.json" ] || fail "dry-run report"
grep -q "no cryptographic validation, scanner validation, or format" \
    "$dry_workspace/results/validation-report.md" || fail "dry-run caveat"
pass "bounded dry-run completes without scanner or cryptographic claims"

printf 'all validation self-tests passed\n'
