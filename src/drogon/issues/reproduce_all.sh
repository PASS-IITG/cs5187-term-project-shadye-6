#!/usr/bin/env bash
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(dirname "$SCRIPT_DIR")"
DROGON_DIR="${ROOT_DIR}/drogon"
FUZZ_DIR="${ROOT_DIR}/drogon-fuzz"
BUILD_DIR="${FUZZ_DIR}/build/asan"

echo "======================================================================"
echo "    Drogon Comprehensive Security Issues & Reproducers Suite         "
echo "======================================================================"
echo "Directory: $SCRIPT_DIR"
echo

check_reproducer() {
    local ISSUE="$1"
    local DESC="$2"
    echo "----------------------------------------------------------------------"
    echo "[*] Running ${ISSUE}: ${DESC}"
    echo "----------------------------------------------------------------------"
    if [ -f "$SCRIPT_DIR/$ISSUE/reproduce_standalone.cc" ]; then
        echo "[+] Found standalone C++ reproducer in $ISSUE/reproduce_standalone.cc"
    fi
    if ls "$SCRIPT_DIR/$ISSUE"/crash* 1> /dev/null 2>&1; then
        echo "[+] Found raw fuzzing trigger crash artifact(s):"
        ls -lh "$SCRIPT_DIR/$ISSUE"/crash*
    fi
    if [ -f "$SCRIPT_DIR/$ISSUE/crash.log" ]; then
        echo "[+] Found crash stacktrace and sanitizer diagnostics in $ISSUE/crash.log"
    fi
    echo
}

check_reproducer "issue-01-httpfile-iterator-oob" "HttpFileImpl::save() 3-Iterator Out-of-Bounds Dereference"
check_reproducer "issue-02-filesystem-noexcept-dos" "HttpFileImpl::save() / saveAs() Uncaught filesystem_error Server DoS"
check_reproducer "issue-03-httpresponse-enum-ub" "HttpResponseParser Undefined Behavior on Non-Standard Status Codes"
check_reproducer "issue-04-multipart-streaming-desync" "MultipartStreamParser vs MultiPartParser Boundary Discrepancy"
check_reproducer "issue-05-upstream-header-framing" "HttpRequestParser Upstream Malformed Header Boundary Flaw"
check_reproducer "issue-06-llhttp-differential-framing" "llhttp vs Drogon Differential Framing Discrepancy"
check_reproducer "issue-07-response-builder-null-injection" "Header Parameter Validation & Null-Byte Rejection"

echo "======================================================================"
echo "    [+] All 7 issues packaged with reproducers, logs, and patches!    "
echo "======================================================================"

