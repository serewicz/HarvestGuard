# shellcheck shell=bash
#
# Shared helpers for the HarvestGuard real-world validation harness (HG-045).
#
# Sourced by validation/run-validation.sh and by every generator under
# validation/generators/. Contains no HarvestGuard product code and imports
# nothing from the package: the harness observes HarvestGuard from the
# outside, exactly as an operator would.
#
# Privacy rule for everything in this file: passphrases and key material are
# never echoed, never written to the manifest, and never stored in a report.
# Generated passphrases carry a per-run marker (see hg_secret_marker) so the
# harness can prove afterwards that no secret leaked into an output file
# without ever recording the secret itself.

set -o pipefail

# Exported so generators and the orchestrator agree on one harness version, and
# so the frozen manifest can record which harness produced it.
export HG_HARNESS_VERSION="1"

# ---------------------------------------------------------------- output ----

hg_heading() {
    printf '\n===============================================================\n'
    printf '%s\n' "$*"
    printf '===============================================================\n'
}

hg_say() {
    printf '%s\n' "$*"
}

hg_bullet() {
    printf '  - %s\n' "$*"
}

hg_warn() {
    printf 'WARNING: %s\n' "$*" >&2
}

hg_err() {
    printf 'ERROR: %s\n' "$*" >&2
}

hg_die() {
    hg_err "$*"
    exit 1
}

hg_assert_within_workspace() {
    local candidate="${1:?path required}"
    local workspace="${HG_WORKSPACE:?HG_WORKSPACE must be set}"
    local resolved parent
    if [ -e "$candidate" ]; then
        resolved="$(cd "$candidate" 2>/dev/null && pwd -P)" ||
            resolved="$(cd "$(dirname "$candidate")" && printf '%s/%s' "$(pwd -P)" "$(basename "$candidate")")"
    else
        parent="$(dirname "$candidate")"
        resolved="$(cd "$parent" && printf '%s/%s' "$(pwd -P)" "$(basename "$candidate")")"
    fi
    case "$resolved" in
        "$workspace" | "$workspace"/*) return 0 ;;
        *) hg_die "refusing path outside validation workspace: $candidate" ;;
    esac
}

hg_redact_command() {
    local text="$*"
    text="$(printf '%s' "$text" | sed -E \
        -e 's/HGVALSECRET-[^[:space:]]+/[REDACTED]/g' \
        -e 's/(pass(word|phrase)?|secret|token)(=|[[:space:]]+)[^[:space:]]+/\1\3[REDACTED]/Ig' \
        -e 's/(-pass(in|out)?[[:space:]]+)[^[:space:]]+/\1[REDACTED]/Ig')"
    printf '%s' "$text"
}

hg_apply_cleanup_choice() {
    local choice="${1:-}"
    case "$choice" in
        delete)
            [ -f "$HG_WORKSPACE/.harvestguard-validation-workspace" ] ||
                hg_die "refusing to delete unmarked workspace: $HG_WORKSPACE"
            chmod -R u+w "$HG_WORKSPACE" 2>/dev/null || true
            rm -rf -- "$HG_WORKSPACE"
            hg_say "Workspace deleted: $HG_WORKSPACE"
            ;;
        keep) hg_say "Workspace retained with explicit approval: $HG_WORKSPACE" ;;
        *) hg_warn "no explicit cleanup choice; workspace retained: $HG_WORKSPACE" ;;
    esac
}

# ------------------------------------------------------------ randomness ----

# Short random hex token. Used for run identity, workspace names, artifact
# names, and disposable passphrases, so that no test depends on a fixed
# filename, path, salt, key, timestamp, or payload.
hg_rand_hex() {
    local bytes="${1:-4}"
    if command -v openssl >/dev/null 2>&1; then
        openssl rand -hex "$bytes"
    else
        # Fallback that still varies per run.
        head -c "$((bytes * 2))" /dev/urandom | od -An -tx1 | tr -d ' \n' | cut -c1-"$((bytes * 2))"
    fi
}

# Random integer in [$1, $2].
hg_rand_int() {
    local low="$1" high="$2" span
    span=$((high - low + 1))
    printf '%s' "$((low + (RANDOM % span)))"
}

# Pick one of the arguments at random.
hg_rand_choice() {
    local count=$#
    local index=$((RANDOM % count))
    shift "$index"
    printf '%s' "$1"
}

# The per-run marker embedded in every disposable passphrase this harness
# generates. Stage 8 greps HarvestGuard's outputs, the manifest, and the
# reports for this marker: a hit means a secret leaked. The marker is a
# prefix of the passphrase, never the passphrase itself, so recording the
# marker records no secret.
hg_secret_marker() {
    printf 'HGVALSECRET-%s' "${HG_RUN_ID:?HG_RUN_ID must be set}"
}

# A disposable, single-use passphrase. Printed nowhere; callers pass it to
# tools through the environment or a mode-0600 file inside the workspace.
hg_disposable_passphrase() {
    printf '%s-%s' "$(hg_secret_marker)" "$(hg_rand_hex 16)"
}

# ------------------------------------------------------------------ misc ----

hg_sha256() {
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$1" | cut -d' ' -f1
    else
        shasum -a 256 "$1" | cut -d' ' -f1
    fi
}

hg_tool_version() {
    local tool="$1"
    case "$tool" in
        openssl) openssl version 2>/dev/null | head -n1 ;;
        # ssh-keygen has no version flag: `-V` is its certificate
        # validity-interval option, so asking it for a version yields the usage
        # error "option requires an argument -- V", which is then recorded as if
        # it were a version string (observed on Ubuntu 24.04, OpenSSH 9.6p1).
        # OpenSSH reports its version through `ssh -V`, on stderr.
        ssh-keygen)
            if command -v ssh >/dev/null 2>&1; then
                ssh -V 2>&1 | head -n1
            else
                printf 'ssh-keygen present (OpenSSH version not reported)'
            fi
            ;;
        age) age --version 2>/dev/null | head -n1 ;;
        *) command -v "$tool" >/dev/null 2>&1 && printf 'present (version not reported)' ;;
    esac
}

# ------------------------------------------------------------------ JSON ----

hg_json_escape() {
    local text="$1"
    text="${text//\\/\\\\}"
    text="${text//\"/\\\"}"
    text="${text//$'\t'/\\t}"
    text="${text//$'\r'/\\r}"
    text="${text//$'\n'/\\n}"
    printf '%s' "$text"
}

# _hg_json_array <delimiter> <list>
#
# Turns a delimited list into a JSON array of strings. Rule IDs never contain
# spaces, so they are space-delimited; asset types do, so those lists are
# pipe-delimited.
_hg_json_array() {
    local delimiter="$1" list="$2"
    if [ -z "$list" ]; then
        printf '[]'
        return
    fi
    local item first=1 out="["
    local previous_ifs="$IFS"
    IFS="$delimiter"
    for item in $list; do
        [ -n "$item" ] || continue
        [ "$first" -eq 1 ] || out+=","
        first=0
        out+="\"$(hg_json_escape "$item")\""
    done
    IFS="$previous_ifs"
    out+="]"
    printf '%s' "$out"
}

# Emit one manifest artifact record as a single JSON line.
#
# Usage: hg_emit_artifact key=value ...
#
# Recognized keys mirror validation/schemas/validation-manifest.schema.json.
# sha256 and size_bytes are deliberately NOT accepted here: they are computed
# at freeze time (stage 6) from the frozen bytes on disk, not asserted by the
# generator that wrote the file.
hg_emit_artifact() {
    local artifact_id="" source_category="generated" relative_path=""
    local generator="" generator_tool="" generator_tool_version=""
    local command_description="" expected_asset_type="" expected_rule_id=""
    local expected_finding_count="0" forbidden_rule_ids="" negative_control="false"
    local forbidden_asset_types="" additional_expected="" expected_scanner_error="false"
    local notes=""
    local pair key value

    for pair in "$@"; do
        key="${pair%%=*}"
        value="${pair#*=}"
        case "$key" in
            artifact_id) artifact_id="$value" ;;
            source_category) source_category="$value" ;;
            relative_path) relative_path="$value" ;;
            generator) generator="$value" ;;
            generator_tool) generator_tool="$value" ;;
            generator_tool_version) generator_tool_version="$value" ;;
            command_description) command_description="$value" ;;
            expected_asset_type) expected_asset_type="$value" ;;
            expected_rule_id) expected_rule_id="$value" ;;
            expected_finding_count) expected_finding_count="$value" ;;
            forbidden_rule_ids) forbidden_rule_ids="$value" ;;
            forbidden_asset_types) forbidden_asset_types="$value" ;;
            additional_expected) additional_expected="$value" ;;
            expected_scanner_error) expected_scanner_error="$value" ;;
            negative_control) negative_control="$value" ;;
            notes) notes="$value" ;;
            *) hg_die "hg_emit_artifact: unknown key '$key'" ;;
        esac
    done

    [ -n "$artifact_id" ] || hg_die "hg_emit_artifact: artifact_id is required"
    [ -n "$relative_path" ] || hg_die "hg_emit_artifact: relative_path is required"

    local forbidden_json asset_forbidden_json additional_json
    forbidden_json="$(_hg_json_array ' ' "$forbidden_rule_ids")"
    # Asset types contain spaces, so those lists are pipe-separated.
    asset_forbidden_json="$(_hg_json_array '|' "$forbidden_asset_types")"
    additional_json="$(_hg_json_array '|' "$additional_expected")"

    printf '{'
    printf '"artifact_id":"%s",' "$(hg_json_escape "$artifact_id")"
    printf '"source_category":"%s",' "$(hg_json_escape "$source_category")"
    printf '"relative_path":"%s",' "$(hg_json_escape "$relative_path")"
    printf '"generator":"%s",' "$(hg_json_escape "$generator")"
    printf '"generator_tool":"%s",' "$(hg_json_escape "$generator_tool")"
    printf '"generator_tool_version":"%s",' "$(hg_json_escape "$generator_tool_version")"
    printf '"command_description":"%s",' "$(hg_json_escape "$command_description")"
    printf '"expected_asset_type":"%s",' "$(hg_json_escape "$expected_asset_type")"
    printf '"expected_rule_id":"%s",' "$(hg_json_escape "$expected_rule_id")"
    printf '"expected_finding_count":%s,' "$expected_finding_count"
    printf '"forbidden_rule_ids":%s,' "$forbidden_json"
    printf '"forbidden_asset_types":%s,' "$asset_forbidden_json"
    printf '"additional_expected":%s,' "$additional_json"
    printf '"expected_scanner_error":%s,' "$expected_scanner_error"
    printf '"negative_control":%s,' "$negative_control"
    printf '"notes":"%s"' "$(hg_json_escape "$notes")"
    printf '}\n'
}

# Generators call this to declare that they cannot run. The orchestrator
# turns it into a `skipped_generators` manifest entry, so an unavailable
# format is visibly skipped rather than silently absent.
hg_emit_skip() {
    local generator="$1" reason="$2"
    printf 'SKIP\t%s\t%s\tskipped\n' "$generator" "$reason"
}

# Reserved for a requested generator identifier or family that this Phase 1
# harness does not implement. Tool absence is a skip, never unsupported.
hg_emit_unsupported() {
    local generator="$1" reason="$2"
    printf 'UNSUPPORTED\t%s\t%s\tunsupported\n' "$generator" "$reason"
}
