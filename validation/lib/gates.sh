# shellcheck shell=bash
#
# The human gate mechanism for the HG-045 validation harness.
#
# The default workflow has exactly eight gates and no stage advances without
# an explicit operator confirmation. `--non-interactive` is the one documented
# way to skip the prompts; it is never the default, it announces itself at
# every gate, and it is recorded in the run log so a report produced that way
# can never be mistaken for an operator-reviewed run.

HG_TOTAL_GATES=8

# Populated by the caller immediately before each hg_gate call.
HG_GATE_WHAT=()
HG_GATE_PATHS=()
HG_GATE_COMMANDS=()
HG_GATE_NEXT=()
HG_GATE_INSPECT=()

hg_gate_reset() {
    HG_GATE_WHAT=()
    HG_GATE_PATHS=()
    HG_GATE_COMMANDS=()
    HG_GATE_NEXT=()
    HG_GATE_INSPECT=()
}

hg_gate_what() { HG_GATE_WHAT+=("$1"); }
hg_gate_path() { HG_GATE_PATHS+=("$1"); }
hg_gate_command() { HG_GATE_COMMANDS+=("$1"); }
hg_gate_next() { HG_GATE_NEXT+=("$1"); }
hg_gate_inspect() { HG_GATE_INSPECT+=("$1"); }

_hg_gate_section() {
    local title="$1"
    shift
    printf '\n%s\n' "$title"
    if [ "$#" -eq 0 ]; then
        printf '  (none)\n'
        return
    fi
    local line
    for line in "$@"; do
        printf '  - %s\n' "$line"
    done
}

# hg_gate <stage-number> <stage-title>
#
# Prints the full gate disclosure and then blocks for confirmation. Returns
# only when the operator explicitly continues; aborts the run otherwise.
hg_gate() {
    local number="$1" title="$2"

    hg_heading "GATE ${number} of ${HG_TOTAL_GATES} — ${title}"

    _hg_gate_section "What just happened:" ${HG_GATE_WHAT[@]+"${HG_GATE_WHAT[@]}"}
    _hg_gate_section "Files and directories created or discovered:" \
        ${HG_GATE_PATHS[@]+"${HG_GATE_PATHS[@]}"}
    _hg_gate_section "Commands executed (secret arguments redacted):" \
        ${HG_GATE_COMMANDS[@]+"${HG_GATE_COMMANDS[@]}"}
    _hg_gate_section "Expected next action:" ${HG_GATE_NEXT[@]+"${HG_GATE_NEXT[@]}"}
    _hg_gate_section "How to inspect the current state:" \
        ${HG_GATE_INSPECT[@]+"${HG_GATE_INSPECT[@]}"}
    _hg_gate_section "How to abort safely:" \
        "Type 'abort' at the prompt below, or press Ctrl-C." \
        "Nothing outside ${HG_WORKSPACE:-the validation workspace} has been written." \
        "Aborting leaves the workspace in place for inspection; remove it yourself with:" \
        "    rm -rf -- '${HG_WORKSPACE:-<workspace>}'"
    _hg_gate_section "How to continue:" \
        "Type 'continue' and press Enter. Empty or unrecognized input never advances."

    if [ "${HG_NON_INTERACTIVE:-0}" = "1" ]; then
        printf '\n[non-interactive] Gate %s auto-approved by --non-interactive.\n' "$number"
        printf '[non-interactive] This run was NOT reviewed by an operator at this gate.\n'
        return 0
    fi

    local answer=""
    while true; do
        printf '\nType continue or abort: '
        if [ "${HG_GATE_STDIN_ONLY:-0}" = "1" ]; then
            IFS= read -r answer || answer=""
        elif [ -r /dev/tty ]; then
            IFS= read -r answer < /dev/tty || answer=""
        else
            IFS= read -r answer || answer=""
        fi
        case "$answer" in
            continue)
                printf 'Confirmed. Continuing.\n'
                return 0
                ;;
            abort)
                hg_say ""
                hg_say "Stopped at gate ${number} (${title}) by operator request."
                hg_say "Workspace retained for inspection: ${HG_WORKSPACE:-<none>}"
                exit 10
                ;;
            *) hg_warn "enter exactly 'continue' or 'abort'; the gate remains closed" ;;
        esac
    done
}

# A yes/no question that is NOT a stage gate (for example the stage 8 cleanup
# offer). Returns 0 for an explicit yes, 1 for anything else. In
# non-interactive mode it returns the caller-supplied default without
# inventing consent.
hg_confirm() {
    local prompt="$1" noninteractive_default="${2:-no}"
    if [ "${HG_NON_INTERACTIVE:-0}" = "1" ]; then
        printf '[non-interactive] %s -> %s (no operator confirmation)\n' \
            "$prompt" "$noninteractive_default"
        [ "$noninteractive_default" = "yes" ]
        return
    fi
    local answer=""
    printf '%s [yes/no]: ' "$prompt"
    if [ "${HG_GATE_STDIN_ONLY:-0}" = "1" ]; then
        IFS= read -r answer || answer=""
    elif [ -r /dev/tty ]; then
        IFS= read -r answer < /dev/tty || answer=""
    else
        IFS= read -r answer || answer=""
    fi
    case "$answer" in
        yes | YES | Yes) return 0 ;;
        *) return 1 ;;
    esac
}

# Free-text operator input (plan notes, generators to disable). Never used for
# secrets. Returns the empty string in non-interactive mode.
hg_prompt_line() {
    local prompt="$1"
    if [ "${HG_NON_INTERACTIVE:-0}" = "1" ]; then
        printf ''
        return 0
    fi
    local answer=""
    printf '%s ' "$prompt" >&2
    if [ "${HG_GATE_STDIN_ONLY:-0}" = "1" ]; then
        IFS= read -r answer || answer=""
    elif [ -r /dev/tty ]; then
        IFS= read -r answer < /dev/tty || answer=""
    else
        IFS= read -r answer || answer=""
    fi
    printf '%s' "$answer"
}
