#!/usr/bin/env bash

# Copyright 2026 The Kruise Authors
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

copyright_base_ref() {
    printf '%s\n' "${1:-${COPYRIGHT_BASE:-1.29.5}}"
}

copyright_validate_base() {
    local base_ref=$1
    if ! git rev-parse --verify --quiet "${base_ref}^{commit}" >/dev/null; then
        printf 'copyright: base ref %q is not a commit\n' "${base_ref}" >&2
        return 1
    fi
}

copyright_path_is_supported() {
    local path=$1
    case "${path}" in
        *.rs|*.proto|*.yaml|*.yml|*.sh|Dockerfile|Dockerfile.*|*/Dockerfile|*/Dockerfile.*)
            ;;
        *)
            return 1
            ;;
    esac

    case "${path}" in
        common/*|vendor/*|out/*|proto/google/*|*/testdata/*)
            return 1
            ;;
    esac

    return 0
}

copyright_is_supported() {
    local path=$1
    copyright_path_is_supported "${path}" || return 1

    [[ -f "${path}" ]]
}

# Files that moved or were adapted from an upstream source need an explicit
# provenance mapping when Git cannot infer their origin from the base tree.
copyright_provenance_path() {
    local path=$1
    local detected_path=$2
    case "${path}" in
        src/state/workload_config.rs)
            printf '%s\n' 'src/state/policy.rs'
            ;;
        *)
            printf '%s\n' "${detected_path}"
            ;;
    esac
}

copyright_changed_files() {
    local base_ref=$1
    local status
    local path
    local old_path

    while IFS= read -r -d '' status; do
        case "${status}" in
            R*|C*)
                IFS= read -r -d '' old_path
                IFS= read -r -d '' path
                ;;
            *)
                IFS= read -r -d '' path
                old_path=${path}
                ;;
        esac
        if copyright_is_supported "${path}"; then
            old_path=$(copyright_provenance_path "${path}" "${old_path}")
            printf '%s\0%s\0' "${path}" "${old_path}"
        fi
    done < <(git diff --name-status -z --find-renames --find-copies-harder --diff-filter=ACMR "${base_ref}" --)

    while IFS= read -r -d '' path; do
        if copyright_is_supported "${path}"; then
            old_path=$(copyright_provenance_path "${path}" '')
            printf '%s\0%s\0' "${path}" "${old_path}"
        fi
    done < <(git ls-files --others --exclude-standard -z)
}

copyright_is_upstream_file() {
    local base_ref=$1
    local base_path=$2
    [[ -n "${base_path}" ]] &&
        copyright_path_is_supported "${base_path}" &&
        git cat-file -e "${base_ref}:${base_path}" 2>/dev/null
}

copyright_comment_prefix() {
    local path=$1
    case "${path}" in
        *.rs|*.proto)
            printf '%s\n' '//'
            ;;
        *)
            printf '%s\n' '#'
            ;;
    esac
}

copyright_count_line() {
    local path=$1
    local line=$2
    awk -v expected="${line}" 'NR <= 30 && $0 == expected { count++ } END { print count + 0 }' "${path}"
}

copyright_has_apache_header() {
    local path=$1
    local prefix=$2
    awk -v prefix="${prefix}" '
        BEGIN {
            expected[1] = prefix " Licensed under the Apache License, Version 2.0 (the \"License\");"
            expected[2] = prefix " you may not use this file except in compliance with the License."
            expected[3] = prefix " You may obtain a copy of the License at"
            expected[4] = prefix
            expected[5] = prefix "     http://www.apache.org/licenses/LICENSE-2.0"
            expected[6] = prefix
            expected[7] = prefix " Unless required by applicable law or agreed to in writing, software"
            expected[8] = prefix " distributed under the License is distributed on an \"AS IS\" BASIS,"
            expected[9] = prefix " WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied."
            expected[10] = prefix " See the License for the specific language governing permissions and"
            expected[11] = prefix " limitations under the License."
        }
        NR > 30 { exit }
        $0 == expected[state + 1] {
            state++
            if (state == 11) found = 1
            next
        }
        $0 == expected[1] { state = 1; next }
        { state = 0 }
        END { exit !found }
    ' "${path}"
}

copyright_preserved_prefix_lines() {
    local path=$1
    case "${path}" in
        *.sh)
            awk 'NR == 1 && /^#!/ { print 1; exit } { print 0; exit }' "${path}"
            ;;
        Dockerfile|Dockerfile.*|*/Dockerfile|*/Dockerfile.*)
            awk '
                BEGIN { IGNORECASE = 1 }
                /^#[[:space:]]*(syntax|escape|check)=/ { count++; next }
                { print count + 0; exit }
                END { if (NR == count) print count + 0 }
            ' "${path}" | head -n 1
            ;;
        *.yaml|*.yml)
            awk '
                NR == 1 && /^%(YAML|TAG)/ { directives = 1 }
                directives && $0 == "---" { print NR; printed = 1; exit }
                directives { next }
                { print 0; printed = 1; exit }
                END { if (!printed) print 0 }
            ' "${path}" | head -n 1
            ;;
        *)
            printf '0\n'
            ;;
    esac
}

copyright_write_header() {
    local prefix=$1
    printf '%s Copyright 2026 The Kruise Authors\n' "${prefix}"
    printf '%s\n' "${prefix}"
    printf '%s Licensed under the Apache License, Version 2.0 (the \"License\");\n' "${prefix}"
    printf '%s you may not use this file except in compliance with the License.\n' "${prefix}"
    printf '%s You may obtain a copy of the License at\n' "${prefix}"
    printf '%s\n' "${prefix}"
    printf '%s     http://www.apache.org/licenses/LICENSE-2.0\n' "${prefix}"
    printf '%s\n' "${prefix}"
    printf '%s Unless required by applicable law or agreed to in writing, software\n' "${prefix}"
    printf '%s distributed under the License is distributed on an \"AS IS\" BASIS,\n' "${prefix}"
    printf '%s WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.\n' "${prefix}"
    printf '%s See the License for the specific language governing permissions and\n' "${prefix}"
    printf '%s limitations under the License.\n' "${prefix}"
}
