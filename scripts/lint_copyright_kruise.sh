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

failed=0
checked=0
while IFS= read -r -d '' path; do
    IFS= read -r -d '' base_path
    checked=$((checked + 1))
    work_path=./${path}
    prefix=$(copyright_comment_prefix "${path}")
    istio_count=$(copyright_count_line "${work_path}" "${prefix} Copyright Istio Authors")
    modification_count=$(copyright_count_line "${work_path}" "${prefix} Modifications Copyright 2026 The Kruise Authors")
    kruise_count=$(copyright_count_line "${work_path}" "${prefix} Copyright 2026 The Kruise Authors")

    if ! copyright_has_apache_header "${work_path}" "${prefix}"; then
        printf 'copyright: %s does not contain a complete Apache 2.0 header\n' "${path}" >&2
        failed=1
    fi

    if copyright_is_upstream_file "${base_ref}" "${base_path}"; then
        if ((istio_count != 1 || modification_count != 1 || kruise_count != 0)); then
            printf 'copyright: %s is derived from %s; expected Istio copyright and Kruise modification notice\n' "${path}" "${base_ref}" >&2
            failed=1
        fi
    else
        if ((kruise_count != 1 || istio_count != 0 || modification_count != 0)); then
            printf 'copyright: %s is new relative to %s; expected Kruise-only copyright\n' "${path}" "${base_ref}" >&2
            failed=1
        fi
    fi
done < <(copyright_changed_files "${base_ref}")

if ((failed)); then
    printf 'copyright: check failed; run scripts/fix_copyright_kruise.sh %q\n' "${base_ref}" >&2
    exit 1
fi

printf 'copyright: checked %d changed files against %s\n' "${checked}" "${base_ref}"
