#!/usr/bin/env bash
#
# Generator: OpenSSH host identity material produced by real `ssh-keygen` —
# a host private key at a canonical basename, its matching public key, and a
# host certificate signed by a disposable CA key.
#
# Negative control: a text file at a canonical host-key basename. The
# documented claim is that the filename alone is never evidence.

set -euo pipefail

HG_GEN_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=../lib/common.sh
. "$HG_GEN_DIR/../lib/common.sh"

GEN_NAME="openssh_host_identity"
GEN_TOOL="ssh-keygen"
GEN_RULES="openssh_host_identity:private_key openssh_host_identity:public_key openssh_host_identity:host_certificate"
GEN_DESC="OpenSSH host keys and host certificates via 'ssh-keygen'"

gen_probe() {
    command -v ssh-keygen >/dev/null 2>&1 || {
        printf 'ssh-keygen is not installed\n'
        exit 3
    }
    hg_tool_version ssh-keygen
}

gen_generate() {
    local outdir="$1" rel="$2"
    local scratch="${HG_SCRATCH_DIR:?HG_SCRATCH_DIR must be set}/$GEN_NAME"
    mkdir -p "$outdir" "$scratch"
    chmod 700 "$scratch"

    local log="$scratch/generator.log"
    : > "$log"
    local version nonce keytype basename_
    version="$(hg_tool_version ssh-keygen)"
    nonce="$(hg_rand_hex 4)"
    keytype="$(hg_rand_choice ed25519 rsa ecdsa)"
    basename_="ssh_host_${keytype}_key"

    local key="$outdir/$basename_"
    ssh-keygen -q -t "$keytype" -N '' -C "hgval-$nonce" -f "$key" >>"$log" 2>&1

    hg_emit_artifact \
        "artifact_id=${GEN_NAME}-private-${nonce}" \
        "source_category=generated" \
        "relative_path=$rel/$basename_" \
        "generator=$GEN_NAME" \
        "generator_tool=ssh-keygen" \
        "generator_tool_version=$version" \
        "command_description=ssh-keygen -q -t $keytype -N '' -C hgval-$nonce -f <artifact> (empty passphrase by design)" \
        "expected_asset_type=OpenSSH Host Private Key Candidate" \
        "expected_rule_id=openssh_host_identity:private_key" \
        "expected_finding_count=1" \
        "negative_control=false" \
        "notes=Unencrypted host key at the canonical basename for key type $keytype."

    hg_emit_artifact \
        "artifact_id=${GEN_NAME}-public-${nonce}" \
        "source_category=generated" \
        "relative_path=$rel/${basename_}.pub" \
        "generator=$GEN_NAME" \
        "generator_tool=ssh-keygen" \
        "generator_tool_version=$version" \
        "command_description=written by the same ssh-keygen invocation as the private key" \
        "expected_asset_type=OpenSSH Host Public Key Candidate" \
        "expected_rule_id=openssh_host_identity:public_key" \
        "expected_finding_count=1" \
        "negative_control=false" \
        "notes=Matching .pub record at the canonical basename."

    # A disposable CA key, kept in scratch so it is never part of the corpus,
    # used to sign a real host certificate.
    ssh-keygen -q -t ed25519 -N '' -C "hgval-ca-$nonce" -f "$scratch/ca_key" >>"$log" 2>&1
    ssh-keygen -q -s "$scratch/ca_key" -I "hgval-$nonce" -h \
        -n "host-${nonce}.example.invalid" -V '+52w' "${key}.pub" >>"$log" 2>&1

    if [ -f "${key}-cert.pub" ]; then
        hg_emit_artifact \
            "artifact_id=${GEN_NAME}-certificate-${nonce}" \
            "source_category=generated" \
            "relative_path=$rel/${basename_}-cert.pub" \
            "generator=$GEN_NAME" \
            "generator_tool=ssh-keygen" \
            "generator_tool_version=$version" \
            "command_description=ssh-keygen -s <scratch-ca-key> -I hgval-$nonce -h -n host-$nonce.example.invalid -V +52w <public-key>" \
            "expected_asset_type=OpenSSH Host Certificate" \
            "expected_rule_id=openssh_host_identity:host_certificate" \
            "expected_finding_count=1" \
            "negative_control=false" \
            "notes=HOST-type certificate signed by a disposable CA key held outside the corpus."
    else
        hg_emit_skip "$GEN_NAME:host_certificate" \
            "ssh-keygen did not produce a host certificate on this system"
    fi

    # Negative control: canonical basename, no key material.
    local decoy_dir="$outdir/decoy_$nonce"
    mkdir -p "$decoy_dir"
    {
        printf '# host key for validation run %s was rotated out of this directory\n' "$nonce"
        printf 'ssh-ed25519 (public key material removed)\n'
    } > "$decoy_dir/ssh_host_ed25519_key"

    hg_emit_artifact \
        "artifact_id=${GEN_NAME}-negative-${nonce}" \
        "source_category=generated" \
        "relative_path=$rel/decoy_$nonce/ssh_host_ed25519_key" \
        "generator=$GEN_NAME" \
        "generator_tool=coreutils" \
        "generator_tool_version=n/a" \
        "command_description=printf prose into a file at the canonical ssh_host_ed25519_key basename" \
        "expected_finding_count=0" \
        "forbidden_rule_ids=openssh_host_identity:private_key openssh_host_identity:public_key" \
        "negative_control=true" \
        "notes=Misleading name and near-match content: a canonical basename is not evidence."
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
