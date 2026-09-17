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

set -euo pipefail

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
# shellcheck source=./scripts/copyright_lib.sh
source "${SCRIPT_DIR}/copyright_lib.sh"

base_ref=$(copyright_base_ref "${1:-}")
copyright_validate_base "${base_ref}"

fixed=0
failed=0
while IFS= read -r -d '' path; do
    IFS= read -r -d '' base_path
    work_path=./${path}
    prefix=$(copyright_comment_prefix "${path}")
    tmp=$(mktemp "${TMPDIR:-/tmp}/copyright.XXXXXX")
    trap 'rm -f "${tmp}" "${tmp}.body"' EXIT
    istio_count=$(copyright_count_line "${work_path}" "${prefix} Copyright Istio Authors")
    modification_count=$(copyright_count_line "${work_path}" "${prefix} Modifications Copyright 2026 The Kruise Authors")
    kruise_count=$(copyright_count_line "${work_path}" "${prefix} Copyright 2026 The Kruise Authors")

    if copyright_is_upstream_file "${base_ref}" "${base_path}"; then
        upstream_file=1
        if ((istio_count == 1 && modification_count == 0 && kruise_count == 0)) &&
            copyright_has_apache_header "${work_path}" "${prefix}"; then
            awk \
                -v old="${prefix} Copyright Istio Authors" \
                -v notice="${prefix} Modifications Copyright 2026 The Kruise Authors" '
                { print }
                NR <= 30 && !inserted && $0 == old { print notice; inserted = 1 }
            ' "${work_path}" >"${tmp}"
        elif ((istio_count == 1 && modification_count == 1 && kruise_count == 0)) &&
            copyright_has_apache_header "${work_path}" "${prefix}"; then
            rm -f "${tmp}"
            trap - EXIT
            continue
        else
            printf 'copyright: cannot safely repair upstream header in %s\n' "${path}" >&2
            failed=1
            rm -f "${tmp}"
            trap - EXIT
            continue
        fi
    else
        upstream_file=0
    fi

    if ((upstream_file == 0)) &&
        ((kruise_count == 1 && istio_count == 0 && modification_count == 0)) &&
        copyright_has_apache_header "${work_path}" "${prefix}"; then
        rm -f "${tmp}"
        trap - EXIT
        continue
    elif ((upstream_file == 0)) &&
        ((kruise_count == 0 && istio_count == 1 && modification_count <= 1)) &&
        copyright_has_apache_header "${work_path}" "${prefix}"; then
        awk \
            -v old="${prefix} Copyright Istio Authors" \
            -v modification="${prefix} Modifications Copyright 2026 The Kruise Authors" \
            -v notice="${prefix} Copyright 2026 The Kruise Authors" '
            NR <= 30 && $0 == modification { next }
            NR <= 30 && $0 == old { print notice; next }
            { print }
        ' "${work_path}" >"${tmp}"
    elif ((upstream_file == 0 && (kruise_count > 0 || istio_count > 0 || modification_count > 0))); then
        printf 'copyright: cannot safely repair incomplete or duplicate header in %s\n' "${path}" >&2
        failed=1
        rm -f "${tmp}"
        trap - EXIT
        continue
    elif ((upstream_file == 0)); then
        preserve_lines=$(copyright_preserved_prefix_lines "${work_path}")
        : >"${tmp}"
        if ((preserve_lines > 0)); then
            head -n "${preserve_lines}" "${work_path}" >"${tmp}"
        fi
        tail -n "+$((preserve_lines + 1))" "${work_path}" >"${tmp}.body"
        {
            if ((preserve_lines > 0)); then
                printf '\n'
            fi
            copyright_write_header "${prefix}"
            printf '\n\n'
        } >>"${tmp}"
        cat "${tmp}.body" >>"${tmp}"
        rm -f "${tmp}.body"
    fi

    if ! copyright_has_apache_header "${tmp}" "${prefix}" ||
        ((upstream_file == 1 &&
            ($(copyright_count_line "${tmp}" "${prefix} Copyright Istio Authors") != 1 ||
                $(copyright_count_line "${tmp}" "${prefix} Modifications Copyright 2026 The Kruise Authors") != 1 ||
                $(copyright_count_line "${tmp}" "${prefix} Copyright 2026 The Kruise Authors") != 0))) ||
        ((upstream_file == 0 &&
            ($(copyright_count_line "${tmp}" "${prefix} Copyright 2026 The Kruise Authors") != 1 ||
                $(copyright_count_line "${tmp}" "${prefix} Copyright Istio Authors") != 0 ||
                $(copyright_count_line "${tmp}" "${prefix} Modifications Copyright 2026 The Kruise Authors") != 0))); then
        printf 'copyright: generated header validation failed for %s\n' "${path}" >&2
        failed=1
        rm -f "${tmp}"
        trap - EXIT
        continue
    fi

    chmod --reference="${work_path}" "${tmp}" 2>/dev/null || chmod "$(stat -f '%Lp' "${work_path}")" "${tmp}"
    mv "${tmp}" "${work_path}"
    trap - EXIT
    printf 'copyright: fixed %s\n' "${path}"
    fixed=$((fixed + 1))
done < <(copyright_changed_files "${base_ref}")

printf 'copyright: fixed %d files against %s\n' "${fixed}" "${base_ref}"
exit "${failed}"
