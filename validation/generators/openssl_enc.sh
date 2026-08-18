#!/usr/bin/env bash
#
# Generator: OpenSSL `Salted__` encrypted files, produced by the real
# `openssl enc` command (never a handcrafted byte string).
#
# Positive controls exercise the documented content-first behavior, including
# a correctly encrypted file carrying a deliberately misleading extension.
# Negative controls are a plaintext file wearing an encrypted extension and a
# near-match file whose header is one byte away from the real signature.

set -euo pipefail

HG_GEN_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=../lib/common.sh
. "$HG_GEN_DIR/../lib/common.sh"

GEN_NAME="openssl_enc"
GEN_TOOL="openssl"
GEN_RULES="encrypted_file:openssl"
GEN_DESC="OpenSSL Salted__ encrypted files via 'openssl enc'"

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
    local version nonce cipher passphrase plaintext
    version="$(hg_tool_version openssl)"
    nonce="$(hg_rand_hex 4)"
    cipher="$(hg_rand_choice aes-256-cbc aes-128-cbc aes-256-ctr)"
    passphrase="$(hg_disposable_passphrase)"
    plaintext="$scratch/plaintext_$nonce"

    # Varying payload size between runs, so nothing depends on a fixed length.
    head -c "$(hg_rand_int 512 4096)" /dev/urandom | base64 > "$plaintext"

    local encrypt_desc="openssl enc -$cipher -pbkdf2 -salt -in <scratch-plaintext>"
    encrypt_desc+=" -out <artifact> -pass env:HG_VALIDATION_PASSPHRASE [passphrase redacted]"

    local positive="$outdir/payload_${nonce}.enc"
    HG_VALIDATION_PASSPHRASE="$passphrase" openssl enc "-$cipher" -pbkdf2 -salt \
        -in "$plaintext" -out "$positive" -pass env:HG_VALIDATION_PASSPHRASE >>"$log" 2>&1

    hg_emit_artifact \
        "artifact_id=${GEN_NAME}-positive-${nonce}" \
        "source_category=generated" \
        "relative_path=$rel/$(basename "$positive")" \
        "generator=$GEN_NAME" \
        "generator_tool=openssl" \
        "generator_tool_version=$version" \
        "command_description=$encrypt_desc" \
        "expected_asset_type=Encrypted File" \
        "expected_rule_id=encrypted_file:openssl" \
        "expected_finding_count=1" \
        "negative_control=false" \
        "notes=Real openssl enc output, conventional .enc extension, cipher $cipher."

    # Same real encryption, deliberately misleading extension: the documented
    # claim is that content is evaluated before any extension-based parsing.
    local misleading="$outdir/quarterly_report_${nonce}.p12"
    HG_VALIDATION_PASSPHRASE="$passphrase" openssl enc "-$cipher" -pbkdf2 -salt \
        -in "$plaintext" -out "$misleading" -pass env:HG_VALIDATION_PASSPHRASE >>"$log" 2>&1

    hg_emit_artifact \
        "artifact_id=${GEN_NAME}-positive-misleading-${nonce}" \
        "source_category=generated" \
        "relative_path=$rel/$(basename "$misleading")" \
        "generator=$GEN_NAME" \
        "generator_tool=openssl" \
        "generator_tool_version=$version" \
        "command_description=$encrypt_desc" \
        "expected_asset_type=Encrypted File" \
        "expected_rule_id=encrypted_file:openssl" \
        "expected_finding_count=1" \
        "negative_control=false" \
        "notes=Real openssl enc output saved with a misleading .p12 extension."

    # Negative control 1: plaintext wearing an encrypted-file extension.
    local plain_named="$outdir/backup_notes_${nonce}.enc"
    {
        printf 'Validation corpus note %s\n' "$nonce"
        printf 'This file is deliberately NOT encrypted despite its extension.\n'
    } > "$plain_named"

    hg_emit_artifact \
        "artifact_id=${GEN_NAME}-negative-extension-${nonce}" \
        "source_category=generated" \
        "relative_path=$rel/$(basename "$plain_named")" \
        "generator=$GEN_NAME" \
        "generator_tool=coreutils" \
        "generator_tool_version=n/a" \
        "command_description=printf plaintext note into a file named *.enc" \
        "expected_finding_count=0" \
        "forbidden_rule_ids=encrypted_file:openssl" \
        "negative_control=true" \
        "notes=Misleading extension: plaintext named .enc must not be reported as encrypted."

    # Negative control 2: near-match content — an eight-byte header that is one
    # character away from the real OpenSSL signature, followed by random bytes.
    local near_match="$outdir/near_match_${nonce}.enc"
    {
        printf 'Salted_X'
        head -c "$(hg_rand_int 64 512)" /dev/urandom
    } > "$near_match"

    hg_emit_artifact \
        "artifact_id=${GEN_NAME}-negative-nearmatch-${nonce}" \
        "source_category=generated" \
        "relative_path=$rel/$(basename "$near_match")" \
        "generator=$GEN_NAME" \
        "generator_tool=coreutils" \
        "generator_tool_version=n/a" \
        "command_description=printf 'Salted_X' followed by random bytes from /dev/urandom" \
        "expected_finding_count=0" \
        "forbidden_rule_ids=encrypted_file:openssl" \
        "negative_control=true" \
        "notes=Near-match content: header differs from Salted__ in one byte."
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
