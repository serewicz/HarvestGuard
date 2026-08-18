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

normal_gate_lines="$(grep -E '^[[:space:]]*hg_gate [1-8] "' "$SELFTEST_ROOT/run-validation.sh")"
[ "$(printf '%s\n' "$normal_gate_lines" | wc -l | tr -d ' ')" -eq 8 ] ||
    fail "normal workflow gate count"
[ "$(printf '%s\n' "$normal_gate_lines" | awk '{print $2}' | paste -sd ' ' -)" = "1 2 3 4 5 6 7 8" ] ||
    fail "normal workflow gate sequence"
set +e
printf 'abort\n' | bash -c ". '$SELFTEST_ROOT/lib/common.sh'; . '$SELFTEST_ROOT/lib/gates.sh'; HG_WORKSPACE='$gate_workspace'; HG_NON_INTERACTIVE=0; HG_GATE_STDIN_ONLY=1; hg_gate_reset; hg_gate 8 'Compare, report, and cleanup'" >/dev/null 2>&1
stage8_abort_status=$?
set -e
[ "$stage8_abort_status" -eq 10 ] || fail "stage 8 abort status"
[ -d "$gate_workspace" ] || fail "stage 8 abort workspace preservation"
grep -q "scan-invocations.tsv" "$SELFTEST_ROOT/run-validation.sh" ||
    fail "durable pre-comparison invocation status record"
pass "normal workflow has eight ordered gates and stage 8 abort preserves workspace"

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
{
    hg_emit_skip age "tool unavailable"
    hg_emit_unsupported pkcs12 "not implemented in Phase 1"
} > "$fixture/state/skipped.tsv"
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
    --out-markdown "$fixture/results/report.md" --console-exit-code 3 \
    --json-exit-code 0 --markdown-exit-code 4 --non-interactive >/dev/null 2>&1 || true
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
assert {item["category"] for item in report["results"]} >= {
    "skipped_generator", "unsupported_generator", "scanner_error"
}
assert report["scan_invocations"] == [
    {"mode": "console", "argv": "harvestguard scan <frozen-corpus>", "exit_status": 3},
    {"mode": "json", "argv": "", "exit_status": 0},
    {"mode": "markdown", "argv": "", "exit_status": 4},
]
PY
pass "comparison preserves manifest, separates outcomes, and records all exit statuses"

symlink_fixture="$SELFTEST_TMP/symlink-freeze"
mkdir -p "$symlink_fixture/corpus/operator-supplied" "$symlink_fixture/state"
printf 'DISTINCTIVE-NONSECRET-OUTSIDE-CONTENT\n' > "$symlink_fixture/outside.txt"
ln -s "$symlink_fixture/outside.txt" \
    "$symlink_fixture/corpus/operator-supplied/outside-link"
cat > "$symlink_fixture/state/artifacts.jsonl" <<'EOF'
{"artifact_id":"explicit-symlink","source_category":"blind","relative_path":"operator-supplied/outside-link","generator":"","generator_tool":"operator-supplied","generator_tool_version":"n/a","command_description":"operator supplied","expected_asset_type":"","expected_rule_id":"","expected_finding_count":0,"forbidden_rule_ids":[],"forbidden_asset_types":[],"additional_expected":[],"expected_scanner_error":false,"negative_control":false,"notes":"explicit symlink rejection self-test"}
EOF
python3 - "$SELFTEST_ROOT/harness_tool.py" "$symlink_fixture" <<'PY'
import importlib.util
from pathlib import Path
from types import SimpleNamespace
import sys

helper_path = Path(sys.argv[1])
fixture = Path(sys.argv[2])
link = fixture / "corpus/operator-supplied/outside-link"

spec = importlib.util.spec_from_file_location("hg_validation_harness_tool", helper_path)
module = importlib.util.module_from_spec(spec)
assert spec.loader is not None
spec.loader.exec_module(module)

original_stat = Path.stat

def guarded_stat(path, *args, **kwargs):
    # Path.is_symlink() is itself an lstat, and on Python 3.12+ it reaches
    # os.stat through Path.stat(follow_symlinks=False). Only a stat that
    # follows the link would touch the target outside the workspace, so that
    # is what this guard rejects.
    if path == link and kwargs.get("follow_symlinks", True):
        raise AssertionError("manifest freeze attempted to stat the symlink target")
    return original_stat(path, *args, **kwargs)

def forbidden_hash(path):
    raise AssertionError(f"manifest freeze attempted to hash symlink target: {path}")

Path.stat = guarded_stat
module._sha256_file = forbidden_hash
args = SimpleNamespace(
    corpus_root=str(fixture / "corpus"),
    records=str(fixture / "state/artifacts.jsonl"),
    out=str(fixture / "state/manifest.json"),
    run_id="symlink-selftest",
    harness_version="1",
    frozen_at="",
    host_os="selftest",
    harvestguard_version="not run",
    secret_marker="",
    scan_command=[],
    skipped="",
    operator_note="",
)
try:
    module.freeze(args)
except SystemExit as exc:
    assert "refusing symbolic link in validation corpus" in str(exc)
else:
    raise AssertionError("manifest freeze accepted an explicit symlink record")
assert not Path(args.out).exists()
PY
pass "manifest freeze rejects explicit corpus symlinks before stat or hash"

osrel="$SELFTEST_TMP/os-release"
mkdir -p "$osrel"
# One fixture per family, so the mapping is asserted without needing a host of
# that distribution. Ubuntu is the validated case; see
# validation/environments/ubuntu-debian.md.
printf 'ID=ubuntu\nID_LIKE=debian\nPRETTY_NAME="Ubuntu 24.04 LTS"\n' > "$osrel/ubuntu"
printf 'ID=debian\nPRETTY_NAME="Debian GNU/Linux 12 (bookworm)"\n' > "$osrel/debian"
printf 'ID=rhel\nID_LIKE="fedora"\nPRETTY_NAME="Red Hat Enterprise Linux 9.4"\n' > "$osrel/rhel"
printf 'ID=arch\nPRETTY_NAME="Arch Linux"\n' > "$osrel/other"
for fixture_case in ubuntu:debian debian:debian rhel:rhel other:unknown; do
    fixture="${fixture_case%%:*}"
    expected="${fixture_case##*:}"
    observed="$(
        HG_OS_RELEASE_FILE="$osrel/$fixture" bash -c \
            ". '$SELFTEST_ROOT/lib/env_inspect.sh'; hg_inspect_environment; printf '%s' \"\$HG_OS_FAMILY\""
    )"
    [ "$observed" = "$expected" ] ||
        fail "os-release family mapping for $fixture (got '$observed', want '$expected')"
done
observed_pretty="$(
    HG_OS_RELEASE_FILE="$osrel/ubuntu" bash -c \
        ". '$SELFTEST_ROOT/lib/env_inspect.sh'; hg_inspect_environment; printf '%s' \"\$HG_OS_DESCRIPTION\""
)"
[ "$observed_pretty" = "Ubuntu 24.04 LTS" ] || fail "os-release description passthrough"
if grep -rqE '\b(apt|apt-get|dnf|yum|zypper|pacman)[[:space:]]' \
    "$SELFTEST_ROOT/run-validation.sh" "$SELFTEST_ROOT/lib" "$SELFTEST_ROOT/generators"; then
    fail "harness references a package manager outside environments/ documentation"
fi
pass "OS-family detection maps Debian and RHEL families without invoking a package manager"

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
