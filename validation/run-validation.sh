#!/usr/bin/env bash
#
# HarvestGuard real-world cryptographic validation harness (HG-045).
#
# An operator-driven, eight-gate validation path for real artifact formats
# produced by the native tools that normally produce them. It is NOT a unit
# test, NOT a replacement for tests/, and NOT proof of complete format support.
#
#   ./validation/run-validation.sh                 # interactive (default)
#   ./validation/run-validation.sh --help
#
# See validation/README.md for the full contract, and validation/environments/
# for the RHEL and CentOS Stream execution notes.

set -euo pipefail

HG_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/common.sh
. "$HG_ROOT/lib/common.sh"
# shellcheck source=lib/gates.sh
. "$HG_ROOT/lib/gates.sh"
# shellcheck source=lib/env_inspect.sh
. "$HG_ROOT/lib/env_inspect.sh"

HG_NON_INTERACTIVE=0
HG_CLEANUP_CHOICE=""
HG_CAPTURE_MARKDOWN=1
HG_WORKSPACE=""
HG_SCAN_MAX_DEPTH=20
HG_HARVESTGUARD_CMD=""
HG_WORKSPACE_MARKER=".harvestguard-validation-workspace"
HG_DRY_RUN=0

usage() {
    cat <<'USAGE'
Usage: run-validation.sh [options]

Options:
  --workspace DIR        Validation workspace to create or reuse. Default: a
                         randomly named directory under $TMPDIR (or /tmp).
  --harvestguard CMD     Installed HarvestGuard CLI executable (default:
                         `harvestguard`). Python module imports are rejected.
  --dry-run              Exercise eight gates, workspace layout, mock manifest,
                         and comparison categories without cryptography or scan claims.
  --max-depth N          --max-depth passed to HarvestGuard (default 20).
  --no-markdown          Skip the optional Markdown capture in stage 7.
  --non-interactive      Documented unattended mode. Every gate is auto-approved
                         and the report records that no operator reviewed the
                         raw results. Requires --cleanup. Never the default.
  --cleanup keep|delete  Pre-declared stage 8 cleanup decision. Required with
                         --non-interactive; ignored otherwise.
  -h, --help             Show this help and exit.

The harness writes only inside the workspace. It installs nothing, needs no
network access, and never uses production credentials.
USAGE
}

while [ $# -gt 0 ]; do
    case "$1" in
        --workspace)
            HG_WORKSPACE="${2:?--workspace needs a directory}"
            shift 2
            ;;
        --harvestguard)
            HG_HARVESTGUARD_CMD="${2:?--harvestguard needs a command}"
            shift 2
            ;;
        --dry-run)
            HG_DRY_RUN=1
            shift
            ;;
        --max-depth)
            HG_SCAN_MAX_DEPTH="${2:?--max-depth needs a number}"
            shift 2
            ;;
        --no-markdown)
            HG_CAPTURE_MARKDOWN=0
            shift
            ;;
        --non-interactive)
            HG_NON_INTERACTIVE=1
            shift
            ;;
        --cleanup)
            HG_CLEANUP_CHOICE="${2:?--cleanup needs keep or delete}"
            shift 2
            ;;
        -h | --help)
            usage
            exit 0
            ;;
        *) hg_die "unknown option: $1 (try --help)" ;;
    esac
done

if [ "$HG_NON_INTERACTIVE" = "1" ] && [ -z "$HG_CLEANUP_CHOICE" ]; then
    hg_die "--non-interactive requires an explicit --cleanup keep|delete decision"
fi
case "${HG_CLEANUP_CHOICE:-}" in
    "" | keep | delete) ;;
    *) hg_die "--cleanup must be 'keep' or 'delete'" ;;
esac
export HG_NON_INTERACTIVE

if [ "$HG_DRY_RUN" = "1" ]; then
    # shellcheck source=lib/dry_run.sh
    . "$HG_ROOT/lib/dry_run.sh"
    hg_run_dry_run "$HG_WORKSPACE"
    exit $?
fi

HG_RUN_ID="$(date -u +%Y%m%dT%H%M%SZ)-$(hg_rand_hex 3)"
export HG_RUN_ID

# ============================================================== stage 1 ====

hg_heading "STAGE 1 of 8 — Environment inspection"

if [ -z "$HG_WORKSPACE" ]; then
    HG_WORKSPACE="${TMPDIR:-/tmp}/harvestguard-validation-$HG_RUN_ID"
fi
if [ -e "$HG_WORKSPACE" ] && [ ! -f "$HG_WORKSPACE/$HG_WORKSPACE_MARKER" ]; then
    hg_die "refusing to reuse unmarked directory as validation workspace: $HG_WORKSPACE"
fi
mkdir -p "$HG_WORKSPACE"
HG_WORKSPACE="$(cd "$HG_WORKSPACE" && pwd)"
case "$HG_WORKSPACE" in
    / | "$HOME") hg_die "refusing unsafe validation workspace: $HG_WORKSPACE" ;;
esac
chmod 700 "$HG_WORKSPACE"
: > "$HG_WORKSPACE/$HG_WORKSPACE_MARKER"
export HG_WORKSPACE

HG_STATE="$HG_WORKSPACE/state"
HG_CORPUS="$HG_WORKSPACE/corpus"
HG_GENERATED="$HG_CORPUS/generated"
HG_OPERATOR="$HG_CORPUS/operator-supplied"
HG_RESULTS="$HG_WORKSPACE/results"
HG_SCRATCH_DIR="$HG_WORKSPACE/scratch"
export HG_SCRATCH_DIR
mkdir -p "$HG_STATE" "$HG_GENERATED" "$HG_OPERATOR" "$HG_RESULTS" "$HG_SCRATCH_DIR"
for guarded_path in "$HG_STATE" "$HG_CORPUS" "$HG_GENERATED" "$HG_OPERATOR" \
    "$HG_RESULTS" "$HG_SCRATCH_DIR"; do
    hg_assert_within_workspace "$guarded_path"
done
chmod 700 "$HG_SCRATCH_DIR"

HG_RECORDS="$HG_STATE/artifacts.jsonl"
HG_SKIPPED="$HG_STATE/skipped.tsv"
HG_RUN_LOG="$HG_STATE/run.log"
: > "$HG_RECORDS"
: > "$HG_SKIPPED"
: > "$HG_RUN_LOG"

hg_log() {
    hg_redact_command "$*" >> "$HG_RUN_LOG"
    printf '\n' >> "$HG_RUN_LOG"
}
hg_log "run_id=$HG_RUN_ID non_interactive=$HG_NON_INTERACTIVE"

if [ -z "$HG_HARVESTGUARD_CMD" ]; then
    HG_HARVESTGUARD_CMD="harvestguard"
fi
case "$HG_HARVESTGUARD_CMD" in
    *" -m "* | python*) hg_die "Stage 7 requires the installed harvestguard CLI, not a Python module" ;;
esac
command -v "$HG_HARVESTGUARD_CMD" >/dev/null 2>&1 ||
    hg_die "installed HarvestGuard CLI not found: $HG_HARVESTGUARD_CMD"
HG_HARVESTGUARD_ARGV=("$HG_HARVESTGUARD_CMD")

hg_inspect_environment
HG_USER="$(id -un) (uid $(id -u))"
HG_PRIVILEGE="unprivileged"
[ "$(id -u)" = "0" ] && HG_PRIVILEGE="root — no generator in this harness requires it"

HG_HARVESTGUARD_VERSION="$("${HG_HARVESTGUARD_ARGV[@]}" --version 2>/dev/null || printf 'not runnable')"
case "$HG_HARVESTGUARD_VERSION" in
    "harvestguard "*) ;;
    *) hg_die "installed CLI did not report HarvestGuard identity: $HG_HARVESTGUARD_VERSION" ;;
esac
HG_HARVESTGUARD_PATH="$(command -v "${HG_HARVESTGUARD_ARGV[0]}" 2>/dev/null || printf '%s' "${HG_HARVESTGUARD_ARGV[0]}")"

hg_say "Operating system: $HG_OS_DESCRIPTION"
hg_say "Kernel:           $HG_KERNEL"
hg_say "Architecture:     $HG_ARCH"
hg_say "Effective user:   $HG_USER"
hg_say "Privilege level:  $HG_PRIVILEGE"
hg_say "HarvestGuard:     $HG_HARVESTGUARD_VERSION"
hg_say "  command:        $HG_HARVESTGUARD_CMD"
hg_say "  resolved path:  $HG_HARVESTGUARD_PATH"

HG_GENERATOR_PATHS=()
while IFS= read -r generator_path; do
    HG_GENERATOR_PATHS+=("$generator_path")
done < <(find "$HG_ROOT/generators" -maxdepth 1 -name '*.sh' | sort)

HG_AVAILABLE=()
HG_AVAILABLE_TOOLS=()
HG_AVAILABLE_RULES=()
HG_AVAILABLE_DESCRIPTIONS=()
HG_UNAVAILABLE=()

hg_say ""
hg_say "Generator tool inventory:"
for generator_path in "${HG_GENERATOR_PATHS[@]}"; do
    IFS=$'\t' read -r gen_name gen_tool gen_rules gen_desc \
        < <(bash "$generator_path" describe)
    if probe_output="$(bash "$generator_path" probe 2>&1)"; then
        HG_AVAILABLE+=("$gen_name")
        HG_AVAILABLE_TOOLS+=("$gen_tool: $probe_output")
        HG_AVAILABLE_RULES+=("$gen_rules")
        HG_AVAILABLE_DESCRIPTIONS+=("$gen_desc")
        hg_bullet "$gen_name — available ($gen_tool: $probe_output)"
    else
        HG_UNAVAILABLE+=("$gen_name	${probe_output:-tool unavailable}")
        hg_bullet "$gen_name — UNAVAILABLE (${probe_output:-tool unavailable})"
    fi
done

[ "${#HG_AVAILABLE[@]}" -gt 0 ] || hg_die "no generator can run on this host; install openssl at minimum"

{
    printf 'run_id: %s\n' "$HG_RUN_ID"
    printf 'os: %s\n' "$HG_OS_DESCRIPTION"
    printf 'os_family: %s\n' "$HG_OS_FAMILY"
    printf 'kernel: %s\n' "$HG_KERNEL"
    printf 'arch: %s\n' "$HG_ARCH"
    printf 'user: %s\n' "$HG_USER"
    printf 'harvestguard: %s\n' "$HG_HARVESTGUARD_VERSION"
    printf 'harvestguard_command: %s\n' "$HG_HARVESTGUARD_CMD"
} > "$HG_STATE/environment.txt"

hg_gate_reset
hg_gate_what "Inspected the operating system, architecture, user, and privilege level."
hg_gate_what "Probed every generator's native tool. No cryptographic artifact exists yet."
hg_gate_what "Created an empty, mode-0700 validation workspace."
hg_gate_path "workspace: $HG_WORKSPACE"
hg_gate_path "corpus root (still empty): $HG_CORPUS"
hg_gate_path "environment record: $HG_STATE/environment.txt"
for entry in ${HG_UNAVAILABLE[@]+"${HG_UNAVAILABLE[@]}"}; do
    hg_gate_path "missing optional tool -> generator skipped: ${entry//$'\t'/ — }"
done
hg_gate_command "uname -sr; uname -m; id -un; id -u"
hg_gate_command "$HG_HARVESTGUARD_CMD --version"
hg_gate_command "validation/generators/*.sh probe (tool presence and version only)"
hg_gate_next "Stage 2 proposes a validation plan. Nothing is generated or scanned yet."
hg_gate_inspect "cat '$HG_STATE/environment.txt'"
hg_gate_inspect "ls -la '$HG_WORKSPACE'"
hg_gate_inspect "Safety boundary: every write goes under '$HG_WORKSPACE'; no network access, no package installation, no production credentials."
hg_gate 1 "Environment inspection"

# ============================================================== stage 2 ====

hg_heading "STAGE 2 of 8 — Validation plan"

hg_say "Proposed generators (each produces at least one positive and one negative control):"
index=0
for name in "${HG_AVAILABLE[@]}"; do
    hg_bullet "$name — ${HG_AVAILABLE_DESCRIPTIONS[$index]}"
    hg_bullet "    expected findings: ${HG_AVAILABLE_RULES[$index]}"
    hg_bullet "    native tool: ${HG_AVAILABLE_TOOLS[$index]}"
    index=$((index + 1))
done

hg_say ""
hg_say "Formats that will be skipped on this host:"
if [ "${#HG_UNAVAILABLE[@]}" -eq 0 ]; then
    hg_bullet "(none)"
else
    for entry in "${HG_UNAVAILABLE[@]}"; do
        hg_bullet "${entry//$'\t'/ — }"
    done
fi
hg_say ""
hg_say "Negative controls in the plan include misleading extensions, misleading"
hg_say "filenames, and near-match content for every generator that runs."

disabled="$(hg_prompt_line 'Generators to DISABLE (space-separated names, empty for none):')"
operator_note="$(hg_prompt_line 'Optional note to record in the manifest:')"

HG_SELECTED=()
for name in "${HG_AVAILABLE[@]}"; do
    skip=0
    for disabled_name in $disabled; do
        [ "$name" = "$disabled_name" ] && skip=1
    done
    if [ "$skip" = "1" ]; then
        hg_emit_skip "$name" "disabled by the operator at stage 2" >> "$HG_SKIPPED"
    else
        HG_SELECTED+=("$name")
    fi
done
for entry in ${HG_UNAVAILABLE[@]+"${HG_UNAVAILABLE[@]}"}; do
    hg_emit_skip "${entry%%$'\t'*}" "${entry#*$'\t'}" >> "$HG_SKIPPED"
done

[ "${#HG_SELECTED[@]}" -gt 0 ] || hg_die "every generator was disabled; nothing to validate"

{
    printf 'selected: %s\n' "${HG_SELECTED[*]}"
    printf 'operator_note: %s\n' "$operator_note"
} > "$HG_STATE/plan.txt"

hg_gate_reset
hg_gate_what "Built the validation plan from the tools actually installed here."
hg_gate_what "Selected generators: ${HG_SELECTED[*]}"
hg_gate_what "Skipped generators are recorded with their reason and stay visible in the report."
hg_gate_path "plan record: $HG_STATE/plan.txt"
hg_gate_path "skip record: $HG_SKIPPED"
hg_gate_command "(no artifact-producing command has run yet)"
hg_gate_next "Stage 3 runs the selected generators. HarvestGuard still does not run."
hg_gate_inspect "cat '$HG_STATE/plan.txt'; cat '$HG_SKIPPED'"
hg_gate 2 "Validation plan"

# ============================================================== stage 3 ====

hg_heading "STAGE 3 of 8 — Generate real artifacts"

for name in "${HG_SELECTED[@]}"; do
    generator_path="$HG_ROOT/generators/$name.sh"
    outdir="$HG_GENERATED/$name"
    hg_say "Running generator: $name"
    if output="$(bash "$generator_path" generate "$outdir" "generated/$name" 2>>"$HG_RUN_LOG")"; then
        while IFS= read -r line; do
            case "$line" in
                '{'*) printf '%s\n' "$line" >> "$HG_RECORDS" ;;
                SKIP*) printf '%s\n' "$line" >> "$HG_SKIPPED" ;;
                '') ;;
                *) hg_log "generator $name emitted unrecognized output: $line" ;;
            esac
        done <<< "$output"
    else
        hg_warn "generator $name failed; recording it as skipped (see $HG_RUN_LOG)"
        hg_emit_skip "$name" "generator failed during stage 3; see state/run.log" >> "$HG_SKIPPED"
    fi
done

redacted_run_log="$(hg_redact_command "$(cat "$HG_RUN_LOG")")"
printf '%s\n' "$redacted_run_log" > "$HG_RUN_LOG"

artifact_count="$(wc -l < "$HG_RECORDS" | tr -d ' ')"
hg_say ""
hg_say "Generated artifact inventory ($artifact_count manifest entries):"
find "$HG_GENERATED" -mindepth 1 | sort | while IFS= read -r path; do
    if [ -d "$path" ]; then
        printf '  [dir ] %s\n' "${path#"$HG_CORPUS"/}"
    else
        printf '  [file] %-58s %8s bytes  sha256=%s\n' \
            "${path#"$HG_CORPUS"/}" "$(wc -c < "$path" | tr -d ' ')" "$(hg_sha256 "$path")"
    fi
done

hg_gate_reset
hg_gate_what "Ran ${#HG_SELECTED[@]} generator(s) using their real native tools."
hg_gate_what "Recorded generator name, tool version, redacted command, and expected finding per artifact."
hg_gate_what "Disposable passphrases were used and are not stored anywhere."
hg_gate_what "HarvestGuard has NOT run."
hg_gate_path "generated corpus: $HG_GENERATED"
hg_gate_path "artifact records: $HG_RECORDS"
hg_gate_path "generator scratch material (never scanned): $HG_SCRATCH_DIR"
hg_gate_command "see the command_description field of each record in $HG_RECORDS"
hg_gate_next "Stage 4 is your inspection window. Nothing will be modified."
hg_gate_inspect "find '$HG_GENERATED' -type f -exec file {} +"
hg_gate_inspect "python3 -m json.tool < <(head -n1 '$HG_RECORDS')"
hg_gate 3 "Generate real artifacts"

# ============================================================== stage 4 ====

hg_heading "STAGE 4 of 8 — Human inspection"

hg_say "Inspect the corpus now, in this or another terminal. The harness will not"
hg_say "touch these files again until you confirm."
hg_say ""
hg_say "Safe inspection commands:"
hg_bullet "file '$HG_GENERATED'/*/*"
hg_bullet "ls -laR '$HG_GENERATED'"
hg_bullet "head -c 16 <artifact> | xxd        # header bytes only"
hg_bullet "openssl x509 -in <certificate> -noout -subject -dates"
hg_bullet "openssl asn1parse -inform DER -in <der-artifact> | head"
hg_say ""
hg_say "Do NOT print or copy:"
hg_bullet "the body of any private key file (*.pem key or ssh_host_* key)"
hg_bullet "the plaintext of any encrypted artifact — nothing here needs decrypting"
hg_bullet "any passphrase; the harness holds none for you to read"

hg_gate_reset
hg_gate_what "Provided inspection guidance only. No file was created, modified, or removed."
hg_gate_path "corpus under inspection: $HG_GENERATED"
hg_gate_command "(none — this stage runs no command against the corpus)"
hg_gate_next "Stage 5 opens a separate directory for files you created yourself."
hg_gate_inspect "ls -laR '$HG_GENERATED'"
hg_gate_inspect "Confirm the generated corpus looks reasonable before continuing."
hg_gate 4 "Human inspection"

# ============================================================== stage 5 ====

hg_heading "STAGE 5 of 8 — Add independent operator files"

HG_DECLARATIONS="$HG_STATE/operator-expectations.tsv"
if [ ! -f "$HG_DECLARATIONS" ]; then
    {
        printf '# One line per operator-supplied file you want to declare.\n'
        printf '# Format (tab-separated):\n'
        printf '#   <path relative to operator-supplied/>\t<expected asset type>\t<expected rule id>\n'
        printf '# Files you do NOT list here are treated as BLIND inputs: they are\n'
        printf '# observed and reported, never judged correct or incorrect.\n'
    } > "$HG_DECLARATIONS"
fi

hg_say "Copy or create independently generated artifacts here:"
hg_say "  $HG_OPERATOR"
hg_say ""
hg_say "The harness will not read their contents, will not modify them, and will not"
hg_say "assume their type. It records only filesystem metadata and a SHA-256 hash."
hg_say ""
hg_say "To declare an expectation for a file, add a line to:"
hg_say "  $HG_DECLARATIONS"
hg_say "Anything left undeclared is a BLIND input."

if [ "$HG_NON_INTERACTIVE" != "1" ]; then
    hg_prompt_line 'Press Enter once your files are in place.' > /dev/null
fi

operator_count=0
blind_count=0
while IFS= read -r path; do
    relative="${path#"$HG_OPERATOR"/}"
    declared_type=""
    declared_rule=""
    while IFS=$'\t' read -r decl_path decl_type decl_rule; do
        case "$decl_path" in '#'* | '') continue ;; esac
        if [ "$decl_path" = "$relative" ]; then
            declared_type="$decl_type"
            declared_rule="$decl_rule"
        fi
    done < "$HG_DECLARATIONS"

    if [ -n "$declared_rule" ]; then
        source_category="operator-supplied"
        expected_count=1
        operator_count=$((operator_count + 1))
        note="Operator-declared expectation, recorded before the scan."
    else
        source_category="blind"
        expected_count=0
        blind_count=$((blind_count + 1))
        note="Blind input: no expectation declared before the scan."
    fi

    hg_emit_artifact \
        "artifact_id=operator-$(printf '%s' "$relative" | tr -c '[:alnum:]' '-')" \
        "source_category=$source_category" \
        "relative_path=operator-supplied/$relative" \
        "generator=" \
        "generator_tool=operator-supplied" \
        "generator_tool_version=n/a" \
        "command_description=supplied by the operator; the harness neither created nor modified it" \
        "expected_asset_type=$declared_type" \
        "expected_rule_id=$declared_rule" \
        "expected_finding_count=$expected_count" \
        "negative_control=false" \
        "notes=$note" >> "$HG_RECORDS"
done < <(find "$HG_OPERATOR" -type f | sort)

hg_say ""
hg_say "Corpus categories now recorded separately:"
hg_bullet "generated:          $(grep -c '"source_category":"generated"' "$HG_RECORDS" || true)"
hg_bullet "operator-declared:  $operator_count"
hg_bullet "blind:              $blind_count"

hg_gate_reset
hg_gate_what "Opened a separate operator-supplied directory and recorded what you placed there."
hg_gate_what "Operator files were hashed and listed only; none was read for content, altered, or moved."
hg_gate_what "Undeclared operator files are marked blind and will not be scored."
hg_gate_path "operator-supplied corpus: $HG_OPERATOR"
hg_gate_path "declaration file: $HG_DECLARATIONS"
hg_gate_command "find '$HG_OPERATOR' -type f (listing and hashing only)"
hg_gate_next "Stage 6 freezes the corpus and the expectations before HarvestGuard runs."
hg_gate_inspect "cat '$HG_DECLARATIONS'; find '$HG_OPERATOR' -type f | sort"
hg_gate 5 "Add independent operator files"

# ============================================================== stage 6 ====

hg_heading "STAGE 6 of 8 — Freeze corpus and expectations"

# Read-only where practical: the generated corpus only. Operator-supplied files
# are deliberately left exactly as the operator left them.
chmod -R a-w "$HG_GENERATED" 2>/dev/null || hg_warn "could not make the generated corpus read-only"

HG_MANIFEST="$HG_STATE/manifest.json"
HG_CONSOLE_OUT="$HG_RESULTS/console.txt"
HG_FINDINGS_JSON="$HG_RESULTS/findings.json"
HG_MARKDOWN_OUT="$HG_RESULTS/report.md"

HG_SCAN_BASE=("${HG_HARVESTGUARD_ARGV[@]}" scan "$HG_CORPUS" --type crypto --max-depth "$HG_SCAN_MAX_DEPTH")
HG_CMD_CONSOLE="${HG_SCAN_BASE[*]}"
HG_CMD_JSON="${HG_SCAN_BASE[*]} --json $HG_FINDINGS_JSON"
HG_CMD_MARKDOWN="${HG_SCAN_BASE[*]} --markdown $HG_MARKDOWN_OUT"

freeze_args=(
    freeze
    --corpus-root "$HG_CORPUS"
    --records "$HG_RECORDS"
    --out "$HG_MANIFEST"
    --run-id "$HG_RUN_ID"
    --harness-version "$HG_HARNESS_VERSION"
    --frozen-at "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    --host-os "$HG_OS_DESCRIPTION"
    --harvestguard-version "$HG_HARVESTGUARD_VERSION"
    --secret-marker "$(hg_secret_marker)"
    --skipped "$HG_SKIPPED"
    --operator-note "$operator_note"
    --scan-command "$HG_CMD_CONSOLE"
    --scan-command "$HG_CMD_JSON"
)
[ "$HG_CAPTURE_MARKDOWN" = "1" ] && freeze_args+=(--scan-command "$HG_CMD_MARKDOWN")

python3 "$HG_ROOT/harness_tool.py" "${freeze_args[@]}"

hg_say ""
hg_say "Exact scan root: $HG_CORPUS"
hg_say "Expected positives, expected negatives, blind inputs, and exclusions are all"
hg_say "recorded in the frozen manifest. Nothing below will rewrite them."

hg_gate_reset
hg_gate_what "Froze the corpus listing, hashed every file, and finalized expectations."
hg_gate_what "Made the generated corpus read-only; operator-supplied files were left untouched."
hg_gate_what "Recorded the exact HarvestGuard commands that stage 7 will run."
hg_gate_path "frozen manifest: $HG_MANIFEST"
hg_gate_path "scan root: $HG_CORPUS"
hg_gate_command "chmod -R a-w '$HG_GENERATED'"
hg_gate_command "$HG_CMD_CONSOLE"
hg_gate_command "$HG_CMD_JSON"
[ "$HG_CAPTURE_MARKDOWN" = "1" ] && hg_gate_command "$HG_CMD_MARKDOWN"
hg_gate_next "Stage 7 runs HarvestGuard against the frozen corpus and stops at the raw output."
hg_gate_inspect "python3 -m json.tool '$HG_MANIFEST' | less"
hg_gate_inspect "grep -c '\"negative_control\": true' '$HG_MANIFEST'"
hg_gate 6 "Freeze corpus and expectations"

# ============================================================== stage 7 ====

hg_heading "STAGE 7 of 8 — Run HarvestGuard and review raw results"

hg_say "Running: $HG_CMD_CONSOLE"
console_status=0
"${HG_SCAN_BASE[@]}" > "$HG_CONSOLE_OUT" 2> "$HG_RESULTS/console.stderr.txt" || console_status=$?

hg_say "Running: $HG_CMD_JSON"
json_status=0
"${HG_SCAN_BASE[@]}" --json "$HG_FINDINGS_JSON" > "$HG_RESULTS/json.stdout.txt" \
    2> "$HG_RESULTS/json.stderr.txt" || json_status=$?

markdown_status=0
if [ "$HG_CAPTURE_MARKDOWN" = "1" ]; then
    hg_say "Running: $HG_CMD_MARKDOWN"
    "${HG_SCAN_BASE[@]}" --markdown "$HG_MARKDOWN_OUT" > "$HG_RESULTS/markdown.stdout.txt" \
        2> "$HG_RESULTS/markdown.stderr.txt" || markdown_status=$?
fi

hg_say ""
hg_say "Exit status — console run: $console_status, JSON run: $json_status, Markdown run: $markdown_status"
hg_say ""
hg_say "----- console output (verbatim) -----"
cat "$HG_CONSOLE_OUT"
hg_say "----- end console output -----"
hg_say ""

if [ -s "$HG_FINDINGS_JSON" ]; then
    python3 "$HG_ROOT/harness_tool.py" summarize --findings "$HG_FINDINGS_JSON"
else
    hg_warn "no JSON findings file was produced"
fi

hg_gate_reset
hg_gate_what "Ran HarvestGuard against the frozen corpus and captured console, JSON, and Markdown output."
hg_gate_what "Reported raw counts, rule IDs, asset types, scanner errors, and coverage limitations."
hg_gate_what "No expectation has been compared yet, and no result has been collapsed into pass/fail."
hg_gate_path "console: $HG_CONSOLE_OUT"
hg_gate_path "JSON findings: $HG_FINDINGS_JSON"
[ "$HG_CAPTURE_MARKDOWN" = "1" ] && hg_gate_path "Markdown: $HG_MARKDOWN_OUT"
hg_gate_path "stderr captures: $HG_RESULTS/*.stderr.txt"
hg_gate_command "$HG_CMD_CONSOLE"
hg_gate_command "$HG_CMD_JSON"
[ "$HG_CAPTURE_MARKDOWN" = "1" ] && hg_gate_command "$HG_CMD_MARKDOWN"
hg_gate_next "Stage 8 compares these results against the frozen manifest — only after you review them."
hg_gate_inspect "less '$HG_CONSOLE_OUT'; python3 -m json.tool '$HG_FINDINGS_JSON' | less"
hg_gate_inspect "Coverage limitation: --type crypto was scanned; other scan types were not exercised."
hg_gate 7 "Run and review raw results"

# ============================================================== stage 8 ====

hg_heading "STAGE 8 of 8 — Compare, report, and clean up"

compare_args=(
    compare
    --manifest "$HG_MANIFEST"
    --findings "$HG_FINDINGS_JSON"
    --console "$HG_CONSOLE_OUT"
    --scan-exit-code "$json_status"
    --out-json "$HG_RESULTS/validation-report.json"
    --out-markdown "$HG_RESULTS/validation-report.md"
)
[ "$HG_CAPTURE_MARKDOWN" = "1" ] && compare_args+=(--markdown "$HG_MARKDOWN_OUT")
[ "$HG_NON_INTERACTIVE" = "1" ] && compare_args+=(--non-interactive)

compare_status=0
python3 "$HG_ROOT/harness_tool.py" "${compare_args[@]}" || compare_status=$?

hg_say ""
hg_say "The comparison used the frozen expectations. Nothing rewrote them."
hg_say "Blind inputs were observed and reported, never scored."
hg_say ""
hg_say "Reports:"
hg_bullet "$HG_RESULTS/validation-report.json"
hg_bullet "$HG_RESULTS/validation-report.md"

hg_say ""
hg_say "Cleanup. The workspace holds generated key material and disposable-passphrase"
hg_say "artifacts. Deleting it removes ONLY '$HG_WORKSPACE'."

cleanup_choice="$HG_CLEANUP_CHOICE"
if [ "$HG_NON_INTERACTIVE" != "1" ]; then
    cleanup_choice="$(hg_prompt_line "Type 'delete' to remove the workspace or 'keep' to retain it:")"
fi
hg_apply_cleanup_choice "$cleanup_choice"

hg_heading "Validation run complete — run ID $HG_RUN_ID"
hg_say "This run validated the artifacts it generated on this host. It does not"
hg_say "establish support for every valid form of any format."
exit "$compare_status"
