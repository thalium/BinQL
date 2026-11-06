#!/bin/bash
set -euo pipefail
set -x  # Uncomment for debugging

# Setup environment
CODEQL_HOME="$(dirname -- "$(command -v codeql)")"
export CODEQL_HOME
export CODEQL_EXTRACTOR_BINARY_TARGET="${PWD}"

# Ensure required env vars
: "${CODEQL_EXTRACTOR_BINARY_WIP_DATABASE:?Must be set}"
: "${CODEQL_EXTRACTOR_BINARY_TRAP_DIR:?Must be set}"
: "${BINQL_TARGET:?Must be set}"
: "${BINQL_IDA_ROOT:?Must be set}"
: "${BINQL_IDA_LOG:?Must be set}"

export IDADIR="${BINQL_IDA_ROOT}"

# Create directories
mkdir -p "${CODEQL_EXTRACTOR_BINARY_WIP_DATABASE}/src"
mkdir -p "${CODEQL_EXTRACTOR_BINARY_WIP_DATABASE}/log/extractor"
mkdir -p "${CODEQL_EXTRACTOR_BINARY_WIP_DATABASE}/trap/binary"
echo "autobuild: Backing up the IDB used in the CodeQL database."
cp "${BINQL_TARGET}" "${CODEQL_EXTRACTOR_BINARY_WIP_DATABASE}/src/$(basename ${BINQL_TARGET})"


echo "autobuild: Using ${BINQL_IDA_ROOT} to extract ${BINQL_TARGET}"
echo "autobuild: Running the extractor..."

EXTRACTOR_LOG="${CODEQL_EXTRACTOR_BINARY_WIP_DATABASE}/log/extractor/ida.log"
EXTRACTOR_PIDFILE="${CODEQL_EXTRACTOR_BINARY_WIP_DATABASE}/log/extractor/extractor.pid"

# Stream the extractor live: tee the full output to the log while forwarding
# [binql] progress lines straight to stdout. No tail -f / log-file polling in
# the path, so lines reach run.py as they are produced. Backgrounding the
# command itself (not a pipeline) keeps $! pointing at the real extractor
# PID, dropped into a pidfile so run.py can send it a targeted soft-stop
# (SIGUSR1) instead of a raw Ctrl+C hitting this whole process tree at once.
# --line-buffered keeps grep flushing per line even though its stdout is a pipe.
# A venv activated by the caller (e.g. extractor/.venv) isn't this project's; drop it so uv stays quiet.
unset VIRTUAL_ENV
PYTHONUNBUFFERED=1 uv run "${CODEQL_HOME}/binary/src/main.py" \
    > >(tee "${EXTRACTOR_LOG}" | grep --line-buffered -F '[binql]') 2>&1 &
EXTRACTOR_PID=$!
echo "${EXTRACTOR_PID}" > "${EXTRACTOR_PIDFILE}"

set +e
wait "${EXTRACTOR_PID}"
EXTRACTOR_STATUS=$?
set -e

if [ "${EXTRACTOR_STATUS}" -ne 0 ]; then
    echo "autobuild: extractor failed (exit ${EXTRACTOR_STATUS})" >&2
    exit "${EXTRACTOR_STATUS}"
fi

# Compress trap files
echo "autobuild: Compressing TRAP files..."
# find "${CODEQL_EXTRACTOR_BINARY_TRAP_DIR}" -name '*.trap' -print0 | xargs -0 -n1 -P$(nproc) gzip -f

echo "autobuild: Extraction complete."

echo ${CODEQL_EXTRACTOR_BINARY_TRAP_DIR}
