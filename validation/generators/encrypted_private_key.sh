#!/usr/bin/env bash
#
# Generator: encrypted private keys in the two forms HarvestGuard claims —
# encrypted PKCS#8 (`ENCRYPTED PRIVATE KEY`, PEM and DER) via `openssl pkcs8`,
# and traditional OpenSSL-style encrypted legacy PEM via `openssl genrsa
# -traditional`.
#
# Negative controls are unencrypted keys wearing encrypted-sounding names: the
# documented claim is that neither the extension nor the filename is evidence.

set -euo pipefail

HG_GEN_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=../lib/common.sh
. "$HG_GEN_DIR/../lib/common.sh"

GEN_NAME="encrypted_private_key"
GEN_TOOL="openssl"
GEN_RULES="private_key:pkcs8_encrypted private_key:legacy_pem_encrypted"
GEN_DESC="Encrypted PKCS#8 (PEM and DER) and encrypted legacy PEM private keys"

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
    local version nonce cipher passphrase plain
    version="$(hg_tool_version openssl)"
    nonce="$(hg_rand_hex 4)"
    cipher="$(hg_rand_choice aes-256-cbc aes-128-cbc)"
    passphrase="$(hg_disposable_passphrase)"
    plain="$scratch/plain_${nonce}.pem"

    openssl genpkey -algorithm RSA -pkeyopt "rsa_keygen_bits:$(hg_rand_choice 2048 3072)" \
        -out "$plain" >>"$log" 2>&1
    chmod 600 "$plain"

    local pkcs8_desc="openssl pkcs8 -topk8 -v2 $cipher -in <scratch-key> -out <artifact>"
    pkcs8_desc+=" -passout env:HG_VALIDATION_PASSPHRASE [passphrase redacted]"

    local pem_key="$outdir/tls_${nonce}_encrypted.pem"
    HG_VALIDATION_PASSPHRASE="$passphrase" openssl pkcs8 -topk8 -v2 "$cipher" \
        -in "$plain" -out "$pem_key" -passout env:HG_VALIDATION_PASSPHRASE >>"$log" 2>&1
    chmod 600 "$pem_key"

    hg_emit_artifact \
        "artifact_id=${GEN_NAME}-pkcs8-pem-${nonce}" \
        "source_category=generated" \
        "relative_path=$rel/$(basename "$pem_key")" \
        "generator=$GEN_NAME" \
        "generator_tool=openssl" \
        "generator_tool_version=$version" \
        "command_description=$pkcs8_desc" \
        "expected_asset_type=Encrypted PKCS#8 Private Key" \
        "expected_rule_id=private_key:pkcs8_encrypted" \
        "expected_finding_count=1" \
        "negative_control=false" \
        "notes=RFC-style ENCRYPTED PRIVATE KEY PEM, PBES2 cipher $cipher."

    local der_key="$outdir/tls_${nonce}_encrypted.der"
    HG_VALIDATION_PASSPHRASE="$passphrase" openssl pkcs8 -topk8 -v2 "$cipher" \
        -in "$plain" -outform DER -out "$der_key" \
        -passout env:HG_VALIDATION_PASSPHRASE >>"$log" 2>&1
    chmod 600 "$der_key"

    hg_emit_artifact \
        "artifact_id=${GEN_NAME}-pkcs8-der-${nonce}" \
        "source_category=generated" \
        "relative_path=$rel/$(basename "$der_key")" \
        "generator=$GEN_NAME" \
        "generator_tool=openssl" \
        "generator_tool_version=$version" \
        "command_description=$pkcs8_desc -outform DER" \
        "expected_asset_type=Encrypted PKCS#8 Private Key" \
        "expected_rule_id=private_key:pkcs8_encrypted" \
        "expected_finding_count=1" \
        "negative_control=false" \
        "notes=Same encrypted key in binary DER form."

    # Traditional OpenSSL-style encrypted PEM (Proc-Type / DEK-Info). OpenSSL 3
    # only writes this form with -traditional; older OpenSSL writes it by
    # default and rejects the flag.
    local legacy_key="$outdir/legacy_${nonce}.key"
    local legacy_ok=0
    if HG_VALIDATION_PASSPHRASE="$passphrase" openssl genrsa -aes128 -traditional \
        -passout env:HG_VALIDATION_PASSPHRASE -out "$legacy_key" 2048 >>"$log" 2>&1; then
        legacy_ok=1
    elif HG_VALIDATION_PASSPHRASE="$passphrase" openssl genrsa -aes128 \
        -passout env:HG_VALIDATION_PASSPHRASE -out "$legacy_key" 2048 >>"$log" 2>&1; then
        legacy_ok=1
    fi

    if [ "$legacy_ok" = "1" ] && grep -q 'Proc-Type: 4,ENCRYPTED' "$legacy_key"; then
        chmod 600 "$legacy_key"
        hg_emit_artifact \
            "artifact_id=${GEN_NAME}-legacy-${nonce}" \
            "source_category=generated" \
            "relative_path=$rel/$(basename "$legacy_key")" \
            "generator=$GEN_NAME" \
            "generator_tool=openssl" \
            "generator_tool_version=$version" \
            "command_description=openssl genrsa -aes128 -traditional -passout env:HG_VALIDATION_PASSPHRASE -out <artifact> 2048 [passphrase redacted]" \
            "expected_asset_type=Encrypted Legacy PEM Private Key" \
            "expected_rule_id=private_key:legacy_pem_encrypted" \
            "expected_finding_count=1" \
            "negative_control=false" \
            "notes=Traditional encrypted PEM with Proc-Type and DEK-Info headers."
    else
        rm -f "$legacy_key"
        hg_emit_skip "$GEN_NAME:legacy_pem" \
            "installed openssl did not produce a Proc-Type/DEK-Info encrypted legacy PEM"
    fi

    # Negative control: an unencrypted key with an encrypted-sounding name.
    local misnamed="$outdir/vault_${nonce}_encrypted_backup.pem"
    cp "$plain" "$misnamed"
    chmod 600 "$misnamed"

    hg_emit_artifact \
        "artifact_id=${GEN_NAME}-negative-misnamed-${nonce}" \
        "source_category=generated" \
        "relative_path=$rel/$(basename "$misnamed")" \
        "generator=$GEN_NAME" \
        "generator_tool=openssl" \
        "generator_tool_version=$version" \
        "command_description=copy of the unencrypted scratch key, saved under an 'encrypted' name" \
        "expected_finding_count=0" \
        "forbidden_rule_ids=private_key:pkcs8_encrypted private_key:legacy_pem_encrypted" \
        "additional_expected=PEM Private Key" \
        "negative_control=true" \
        "notes=Misleading filename: an unencrypted key must not be reported as encrypted (it is expected to appear under the generic PEM private-key rule instead)."

    # Negative control: near-match content — legacy headers with no key body.
    local header_only="$outdir/legacy_${nonce}_header_only.key"
    {
        printf -- '-----BEGIN RSA PRIVATE KEY-----\n'
        printf 'Proc-Type: 4,ENCRYPTED\n'
        printf 'DEK-Info: AES-128-CBC,00000000000000000000000000000000\n'
        printf '\n'
    } > "$header_only"

    hg_emit_artifact \
        "artifact_id=${GEN_NAME}-negative-headeronly-${nonce}" \
        "source_category=generated" \
        "relative_path=$rel/$(basename "$header_only")" \
        "generator=$GEN_NAME" \
        "generator_tool=coreutils" \
        "generator_tool_version=n/a" \
        "command_description=printf legacy PEM encryption headers with no base64 body and no END line" \
        "expected_finding_count=0" \
        "forbidden_rule_ids=private_key:legacy_pem_encrypted" \
        "additional_expected=Encrypted PEM Private Key" \
        "expected_scanner_error=true" \
        "negative_control=true" \
        "notes=Near-match content: headers present, body and END boundary absent."
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
