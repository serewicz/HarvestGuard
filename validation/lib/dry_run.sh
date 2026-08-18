# shellcheck shell=bash

hg_run_dry_run() {
    local requested_workspace="${1:-}"
    HG_RUN_ID="dry-run-$(date -u +%Y%m%dT%H%M%SZ)-$(hg_rand_hex 2)"
    export HG_RUN_ID
    HG_NON_INTERACTIVE=1
    export HG_NON_INTERACTIVE

    if [ -z "$requested_workspace" ]; then
        requested_workspace="${TMPDIR:-/tmp}/harvestguard-validation-$HG_RUN_ID"
    fi
    if [ -e "$requested_workspace" ] &&
        [ ! -f "$requested_workspace/.harvestguard-validation-workspace" ]; then
        hg_die "refusing to reuse a directory not created as a validation workspace"
    fi
    mkdir -p "$requested_workspace"
    HG_WORKSPACE="$(cd "$requested_workspace" && pwd -P)"
    export HG_WORKSPACE
    chmod 700 "$HG_WORKSPACE"
    : > "$HG_WORKSPACE/.harvestguard-validation-workspace"

    local state="$HG_WORKSPACE/state"
    local corpus="$HG_WORKSPACE/corpus"
    local generated="$corpus/generated/mock"
    local operator="$corpus/operator-supplied"
    local results="$HG_WORKSPACE/results"
    local scratch="$HG_WORKSPACE/scratch"
    mkdir -p "$state" "$generated" "$operator" "$results" "$scratch"
    for path in "$state" "$corpus" "$generated" "$operator" "$results" "$scratch"; do
        hg_assert_within_workspace "$path"
    done

    hg_heading "DRY RUN — no cryptographic or scanner validation is performed"
    hg_say "This mode exercises control flow, layout, manifest shape, and comparison categories only."

    local stage
    for stage in 1 2; do
        hg_gate_reset
        hg_gate_what "Dry-run control-flow simulation; no native generator or scanner ran."
        hg_gate_path "workspace: $HG_WORKSPACE"
        hg_gate_next "Advance to the next simulated stage."
        hg_gate "$stage" "$([ "$stage" = 1 ] && printf 'Environment inspection' || printf 'Validation plan')"
    done

    printf 'dry-run mock bytes\n' > "$generated/mock.bin"
    cat > "$state/artifacts.jsonl" <<'EOF'
{"artifact_id":"dry-run-negative","source_category":"generated","relative_path":"generated/mock/mock.bin","generator":"dry_run","generator_tool":"none","generator_tool_version":"n/a","command_description":"mock write inside validation workspace","expected_asset_type":"","expected_rule_id":"","expected_finding_count":0,"forbidden_rule_ids":[],"forbidden_asset_types":[],"additional_expected":[],"expected_scanner_error":false,"negative_control":true,"notes":"Control-flow observation only."}
EOF
    : > "$state/skipped.tsv"

    for stage in 3 4 5; do
        hg_gate_reset
        hg_gate_what "Created or inspected mock dry-run records only."
        hg_gate_path "mock corpus: $corpus"
        hg_gate_next "Advance to the next simulated stage."
        case "$stage" in
            3) title="Generate real artifacts (mocked in dry-run)" ;;
            4) title="Human inspection" ;;
            5) title="Add independent operator files" ;;
        esac
        hg_gate "$stage" "$title"
    done

    python3 "$HG_ROOT/harness_tool.py" freeze \
        --corpus-root "$corpus" --records "$state/artifacts.jsonl" \
        --out "$state/manifest.json" --run-id "$HG_RUN_ID" \
        --harness-version "$HG_HARNESS_VERSION" --host-os "dry-run" \
        --harvestguard-version "not run" --skipped "$state/skipped.tsv" \
        --scan-command "not run in dry-run mode"
    hg_gate_reset
    hg_gate_what "Froze the mock manifest without running HarvestGuard."
    hg_gate_path "manifest: $state/manifest.json"
    hg_gate_next "Stage 7 writes mock raw observations."
    hg_gate 6 "Freeze corpus and expectations"

    printf '[]\n' > "$results/findings.json"
    printf 'dry-run: HarvestGuard was not invoked\n' > "$results/console.txt"
    hg_gate_reset
    hg_gate_what "Recorded mock raw observations; no scanner ran."
    hg_gate_path "mock findings: $results/findings.json"
    hg_gate_next "Stage 8 compares mock records."
    hg_gate 7 "Run and review raw results (mocked in dry-run)"

    python3 "$HG_ROOT/harness_tool.py" compare \
        --manifest "$state/manifest.json" --findings "$results/findings.json" \
        --console "$results/console.txt" --out-json "$results/validation-report.json" \
        --out-markdown "$results/validation-report.md" --non-interactive --dry-run
    hg_gate_reset
    hg_gate_what "Compared mock observations; no format-support conclusion is possible."
    hg_gate_path "mock report: $results/validation-report.json"
    hg_gate_next "Dry-run complete; workspace remains for inspection."
    hg_gate 8 "Compare, report, and cleanup"

    hg_say "Dry-run complete. Workspace retained: $HG_WORKSPACE"
    hg_say "No cryptographic validation, scanner validation, or format support was claimed."
}
