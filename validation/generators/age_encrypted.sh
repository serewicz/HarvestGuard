#!/usr/bin/env bash
#
# Generator: native age v1 encrypted files produced by real `age`, using a
# disposable identity created by `age-keygen` and kept outside the corpus.
#
# Negative control: near-match content that opens with the age version line
# but has no recipient stanza, header MAC, or payload.

set -euo pipefail

HG_GEN_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=../lib/common.sh
. "$HG_GEN_DIR/../lib/common.sh"

GEN_NAME="age_encrypted"
GEN_TOOL="age"
GEN_RULES="encrypted_file:age"
GEN_DESC="Native age v1 encrypted files via 'age -r'"

gen_probe() {
    command -v age >/dev/null 2>&1 || {
        printf 'age is not installed\n'
        exit 3
    }
    command -v age-keygen >/dev/null 2>&1 || {
        printf 'age-keygen is not installed\n'
        exit 3
    }
    hg_tool_version age
}

gen_generate() {
    local outdir="$1" rel="$2"
    local scratch="${HG_SCRATCH_DIR:?HG_SCRATCH_DIR must be set}/$GEN_NAME"
    mkdir -p "$outdir" "$scratch"
    chmod 700 "$scratch"

    local log="$scratch/generator.log"
    : > "$log"
    local version nonce identity recipient
    version="$(hg_tool_version age)"
    nonce="$(hg_rand_hex 4)"
    identity="$scratch/identity_${nonce}.txt"

    ( umask 077 && age-keygen -o "$identity" >>"$log" 2>&1 )
    recipient="$(grep -o 'age1[0-9a-z]\{20,\}' "$identity" | head -n1)"
    [ -n "$recipient" ] || hg_die "$GEN_NAME: could not read a recipient from age-keygen output"

    local plaintext="$scratch/message_${nonce}.txt"
    head -c "$(hg_rand_int 256 2048)" /dev/urandom | base64 > "$plaintext"

    local artifact="$outdir/vault_${nonce}.age"
    age -r "$recipient" -o "$artifact" "$plaintext" >>"$log" 2>&1

    hg_emit_artifact \
        "artifact_id=${GEN_NAME}-positive-${nonce}" \
        "source_category=generated" \
        "relative_path=$rel/$(basename "$artifact")" \
        "generator=$GEN_NAME" \
        "generator_tool=age" \
        "generator_tool_version=$version" \
        "command_description=age-keygen -o <scratch-identity>; age -r <recipient> -o <artifact> <scratch-message> [identity kept outside the corpus]" \
        "expected_asset_type=Encrypted File" \
        "expected_rule_id=encrypted_file:age" \
        "expected_finding_count=1" \
        "negative_control=false" \
        "notes=Native (non-armored) age v1 file; the recipient identity is not recorded."

    local decoy="$outdir/vault_${nonce}_notes.age"
    {
        printf 'age-encryption.org/v1\n'
        printf 'notes about the age rollout for validation run %s\n' "$nonce"
    } > "$decoy"

    hg_emit_artifact \
        "artifact_id=${GEN_NAME}-negative-${nonce}" \
        "source_category=generated" \
        "relative_path=$rel/$(basename "$decoy")" \
        "generator=$GEN_NAME" \
        "generator_tool=coreutils" \
        "generator_tool_version=n/a" \
        "command_description=printf the age version line plus prose into a .age file" \
        "expected_finding_count=0" \
        "forbidden_rule_ids=encrypted_file:age" \
        "negative_control=true" \
        "notes=Near-match content: version line only, no stanza, MAC line, or payload."
}

case "${1:-}" in
    probe) gen_probe ;;
    describe) printf '%s\t%s\t%s\t%s\n' "$GEN_NAME" "$GEN_TOOL" "$GEN_RULES" "$GEN_DESC" ;;
    generate)
        shift
        gen_generate "${1:?outdir required}" "${2:?relative prefix required}"
        ;;
    *) hg_die "usage: $0 {probe|describe|generate <outdir> <relative-prefix>}" ;;
esac
