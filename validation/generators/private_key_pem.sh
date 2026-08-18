#!/usr/bin/env bash
#
# Generator: unencrypted PEM private keys produced by `openssl genpkey`.
#
# The negative control is a redaction placeholder saved with a .pem extension:
# a misleading extension plus near-match content, with no key material.

set -euo pipefail

HG_GEN_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=../lib/common.sh
. "$HG_GEN_DIR/../lib/common.sh"

GEN_NAME="private_key_pem"
GEN_TOOL="openssl"
GEN_RULES="asset type: PEM Private Key (no rule ID published)"
GEN_DESC="Unencrypted PKCS#8 PEM private keys via 'openssl genpkey'"

gen_probe() {
    command -v openssl >/dev/null 2>&1 || {
        printf 'openssl is not installed\n'
        exit 3
    }
    hg_tool_version openssl
}

gen_generate() {
    local outdir="$1" rel="$2"
    local scratch="${HG_SCRATCH_DIR:?HG_SCRATCH_DIR must be set}/$GEN_NAME"
    mkdir -p "$outdir" "$scratch"
    chmod 700 "$scratch"

    local log="$scratch/generator.log"
    : > "$log"
    local version nonce algorithm
    version="$(hg_tool_version openssl)"
    nonce="$(hg_rand_hex 4)"
    algorithm="$(hg_rand_choice rsa ec)"

    # A nested subdirectory, whose depth varies between runs, so no test
    # depends on a fixed path shape.
    local depth subdir="$outdir"
    local relsub="$rel"
    depth="$(hg_rand_int 0 2)"
    local i
    for ((i = 0; i < depth; i++)); do
        subdir="$subdir/level$((i + 1))_$(hg_rand_hex 2)"
        relsub="$relsub/$(basename "$subdir")"
    done
    mkdir -p "$subdir"

    local key="$subdir/app_${nonce}.pem"
    local desc
    if [ "$algorithm" = "rsa" ]; then
        local bits
        bits="$(hg_rand_choice 2048 3072)"
        openssl genpkey -algorithm RSA -pkeyopt "rsa_keygen_bits:$bits" -out "$key" \
            >>"$log" 2>&1
        desc="openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:$bits -out <artifact>"
    else
        local curve
        curve="$(hg_rand_choice P-256 P-384)"
        openssl genpkey -algorithm EC -pkeyopt "ec_paramgen_curve:$curve" -out "$key" \
            >>"$log" 2>&1
        desc="openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:$curve -out <artifact>"
    fi
    chmod 600 "$key"

    hg_emit_artifact \
        "artifact_id=${GEN_NAME}-positive-${nonce}" \
        "source_category=generated" \
        "relative_path=$relsub/$(basename "$key")" \
        "generator=$GEN_NAME" \
        "generator_tool=openssl" \
        "generator_tool_version=$version" \
        "command_description=$desc" \
        "expected_asset_type=PEM Private Key" \
        "expected_finding_count=1" \
        "negative_control=false" \
        "notes=Unencrypted private key, algorithm $algorithm, nesting depth $depth."

    local placeholder="$outdir/app_${nonce}_backup.pem"
    {
        printf '# private key for validation run %s is held in the operator vault\n' "$nonce"
        printf 'BEGIN PRIVATE KEY (placeholder, not a PEM block)\n'
    } > "$placeholder"

    hg_emit_artifact \
        "artifact_id=${GEN_NAME}-negative-${nonce}" \
        "source_category=generated" \
        "relative_path=$rel/$(basename "$placeholder")" \
        "generator=$GEN_NAME" \
        "generator_tool=coreutils" \
        "generator_tool_version=n/a" \
        "command_description=printf a redaction placeholder into a file named *.pem" \
        "expected_finding_count=0" \
        "forbidden_asset_types=PEM Private Key|Encrypted PEM Private Key" \
        "negative_control=true" \
        "notes=Near-match content and misleading extension: no PEM block boundaries."
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
