# shellcheck shell=bash

hg_parse_os_release_file() {
    local release_file="${1:?os-release path required}"
    local line key value
    HG_OS_RELEASE_ID=""
    HG_OS_RELEASE_ID_LIKE=""
    HG_OS_RELEASE_PRETTY_NAME=""
    HG_OS_RELEASE_NAME=""

    while IFS= read -r line || [ -n "$line" ]; do
        case "$line" in
            ID=* | ID_LIKE=* | PRETTY_NAME=* | NAME=*) ;;
            *) continue ;;
        esac
        key="${line%%=*}"
        value="${line#*=}"
        case "$value" in
            \"*\") value="${value#\"}"; value="${value%\"}" ;;
            \'*\') value="${value#\'}"; value="${value%\'}" ;;
        esac
        case "$key" in
            ID) HG_OS_RELEASE_ID="$value" ;;
            ID_LIKE) HG_OS_RELEASE_ID_LIKE="$value" ;;
            PRETTY_NAME) HG_OS_RELEASE_PRETTY_NAME="$value" ;;
            NAME) HG_OS_RELEASE_NAME="$value" ;;
        esac
    done < "$release_file"
}

hg_apply_os_release_file() {
    local release_file="${1:?os-release path required}"
    hg_parse_os_release_file "$release_file"
    HG_OS_DESCRIPTION="${HG_OS_RELEASE_PRETTY_NAME:-${HG_OS_RELEASE_NAME:-unknown}}"
    case " $HG_OS_RELEASE_ID $HG_OS_RELEASE_ID_LIKE " in
            *" rhel "* | *" centos "* | *" fedora "*) HG_OS_FAMILY="rhel" ;;
            *" ubuntu "* | *" debian "*) HG_OS_FAMILY="debian" ;;
    esac
}

hg_inspect_environment() {
    HG_OS_FAMILY="unknown"
    HG_OS_DESCRIPTION="unknown"
    if [ -r /etc/os-release ]; then
        hg_apply_os_release_file /etc/os-release
    elif [ "$(uname -s)" = "Darwin" ]; then
        HG_OS_FAMILY="darwin"
        HG_OS_DESCRIPTION="macOS $(sw_vers -productVersion 2>/dev/null || printf unknown)"
    fi
    HG_ARCH="$(uname -m)"
    HG_KERNEL="$(uname -sr)"
    export HG_OS_FAMILY HG_OS_DESCRIPTION HG_ARCH HG_KERNEL
}
