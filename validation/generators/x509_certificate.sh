#!/usr/bin/env bash
#
# Generator: real X.509 certificates in PEM and DER form, produced by
# `openssl req -x509`.
#
# Negative controls are near-match text: an incomplete PEM block (a BEGIN
# line with no body or END line) and a redaction placeholder saved with a
# certificate extension.

set -euo pipefail

HG_GEN_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=../lib/common.sh
. "$HG_GEN_DIR/../lib/common.sh"

GEN_NAME="x509_certificate"
GEN_TOOL="openssl"
GEN_RULES="asset types: PEM Certificate, DER Certificate (no rule ID published)"
GEN_DESC="PEM and DER X.509 certificates via 'openssl req -x509'"

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
    local version nonce keyspec days subject
    version="$(hg_tool_version openssl)"
    nonce="$(hg_rand_hex 4)"
    keyspec="$(hg_rand_choice rsa:2048 rsa:3072 ec)"
    days="$(hg_rand_int 30 3650)"
    subject="/CN=hgval-${nonce}.example.invalid/O=HarvestGuard Validation"

    local newkey_args=(-newkey "$keyspec")
    if [ "$keyspec" = "ec" ]; then
        local curve
        curve="$(hg_rand_choice prime256v1 secp384r1)"
        newkey_args=(-newkey "ec" -pkeyopt "ec_paramgen_curve:$curve")
    fi

    local pem_cert="$outdir/service_${nonce}.pem"
    openssl req -x509 "${newkey_args[@]}" -nodes -sha256 -days "$days" \
        -subj "$subject" -keyout "$scratch/key_${nonce}.pem" -out "$pem_cert" \
        >>"$log" 2>&1

    local desc="openssl req -x509 -newkey $keyspec -nodes -sha256 -days $days"
    desc+=" -subj '$subject' -keyout <scratch-key> -out <artifact>"

    hg_emit_artifact \
        "artifact_id=${GEN_NAME}-pem-${nonce}" \
        "source_category=generated" \
        "relative_path=$rel/$(basename "$pem_cert")" \
        "generator=$GEN_NAME" \
        "generator_tool=openssl" \
        "generator_tool_version=$version" \
        "command_description=$desc" \
        "expected_asset_type=PEM Certificate" \
        "expected_finding_count=1" \
        "negative_control=false" \
        "notes=Self-signed certificate, key spec $keyspec, validity $days days."

    local der_cert="$outdir/service_${nonce}.der"
    openssl x509 -in "$pem_cert" -outform DER -out "$der_cert" >>"$log" 2>&1

    hg_emit_artifact \
        "artifact_id=${GEN_NAME}-der-${nonce}" \
        "source_category=generated" \
        "relative_path=$rel/$(basename "$der_cert")" \
        "generator=$GEN_NAME" \
        "generator_tool=openssl" \
        "generator_tool_version=$version" \
        "command_description=openssl x509 -in <pem-certificate> -outform DER -out <artifact>" \
        "expected_asset_type=DER Certificate" \
        "expected_finding_count=1" \
        "negative_control=false" \
        "notes=Same certificate re-encoded as DER."

    # Negative control 1: near-match content — a PEM header with no body and
    # no END line, which is not a complete certificate block.
    local truncated="$outdir/archived_cert_${nonce}.pem"
    {
        printf '# certificate archived off-host on request %s\n' "$nonce"
        printf -- '-----BEGIN CERTIFICATE-----\n'
        printf '(body removed before this corpus was assembled)\n'
    } > "$truncated"

    hg_emit_artifact \
        "artifact_id=${GEN_NAME}-negative-truncated-${nonce}" \
        "source_category=generated" \
        "relative_path=$rel/$(basename "$truncated")" \
        "generator=$GEN_NAME" \
        "generator_tool=coreutils" \
        "generator_tool_version=n/a" \
        "command_description=printf an incomplete PEM CERTIFICATE header into a .pem file" \
        "expected_finding_count=0" \
        "forbidden_asset_types=PEM Certificate|DER Certificate" \
        "additional_expected=Malformed PEM Certificate" \
        "expected_scanner_error=true" \
        "negative_control=true" \
        "notes=Near-match content: BEGIN line only, no base64 body and no END line."

    # Negative control 2: ordinary prose wearing a certificate extension.
    local prose="$outdir/renewal_notes_${nonce}.crt"
    printf 'Renewal notes for validation run %s. No certificate material here.\n' \
        "$nonce" > "$prose"

    hg_emit_artifact \
        "artifact_id=${GEN_NAME}-negative-extension-${nonce}" \
        "source_category=generated" \
        "relative_path=$rel/$(basename "$prose")" \
        "generator=$GEN_NAME" \
        "generator_tool=coreutils" \
        "generator_tool_version=n/a" \
        "command_description=printf prose into a file named *.crt" \
        "expected_finding_count=0" \
        "forbidden_asset_types=PEM Certificate|DER Certificate" \
        "additional_expected=Malformed DER Certificate|Malformed PEM Certificate" \
        "expected_scanner_error=true" \
        "negative_control=true" \
        "notes=Misleading extension: prose named .crt must not be reported as a certificate."
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
