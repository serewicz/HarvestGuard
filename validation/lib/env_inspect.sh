# shellcheck shell=bash

hg_inspect_environment() {
    HG_OS_FAMILY="unknown"
    HG_OS_DESCRIPTION="unknown"
    if [ -r /etc/os-release ]; then
        local os_id="" os_like="" pretty=""
        # shellcheck disable=SC1091
        eval "$(. /etc/os-release; printf 'os_id=%q\nos_like=%q\npretty=%q\n' \
            "${ID:-}" "${ID_LIKE:-}" "${PRETTY_NAME:-${NAME:-unknown}}")"
        HG_OS_DESCRIPTION="$pretty"
        case " $os_id $os_like " in
            *" rhel "* | *" centos "* | *" fedora "*) HG_OS_FAMILY="rhel" ;;
            *" ubuntu "* | *" debian "*) HG_OS_FAMILY="debian" ;;
        esac
    elif [ "$(uname -s)" = "Darwin" ]; then
        HG_OS_FAMILY="darwin"
        HG_OS_DESCRIPTION="macOS $(sw_vers -productVersion 2>/dev/null || printf unknown)"
    fi
    HG_ARCH="$(uname -m)"
    HG_KERNEL="$(uname -sr)"
    export HG_OS_FAMILY HG_OS_DESCRIPTION HG_ARCH HG_KERNEL
}
