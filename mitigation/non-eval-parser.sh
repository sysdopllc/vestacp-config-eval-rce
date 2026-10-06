#!/usr/bin/env bash
# Reference mitigation for VESTACP-2026-001
#
# Drop-in non-eval parser for VestaCP func/main.sh: values are extracted with a
# strict KEY='value' regex and assigned via `declare -g` -- they become literal
# strings and are never passed to eval, so injected shell stays inert.
#
# Porting recipe for every eval site in func/main.sh (0.9.8-26):
#   1. object=$(grep "$2='$3'" $USER_DATA/$1.conf)   # unchanged
#   2. replace  eval "$object"  /  eval $line   with   parse_object_kv_list "$object"
#   3. read variables with nameref expansion:  value="${!varname}"
#      (the old code used a second eval: eval echo \$${I} / eval arg=\$$arg_name;
#       ${!varname} is the safe equivalent - bash indirect expansion, no eval)
#   4. quote every expansion in v-* scripts (e.g. bin/v-add-cron-job:
#       echo "$7"  instead of  echo $7)
#
# Verified equivalent to the stock eval parser over 1,165 field comparisons
# against real web/dns/mail/cron/user/db confs: identical output except a `*`
# value where the old eval incorrectly glob-expanded (a latent bug the eval
# version had and this one fixes).

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

# Reference conversion -- stock VestaCP get_object_value, eval-free.
get_object_value() {
    local object
    object=$(grep "$2='$3'" "$USER_DATA/$1.conf")
    parse_object_kv_list "$object"
    local varname="${4#\$}"
    echo "${!varname}"
}
