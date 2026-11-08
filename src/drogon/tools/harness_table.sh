# Sourced by run scripts. name | dict | max_len | timeout(s) | weight (relative CPU share)
# Weights encode attack-surface priority: the request parser (the only surface reachable by an
# unauthenticated remote peer before any routing) and the multipart/body parsers get the most CPU;
# the client-side response parser and the pure codec/range helpers get less.
HARNESSES="
fuzz_http_request    http.dict        1048576 15 6
fuzz_multipart       multipart.dict   1048576 15 5
fuzz_multipart_form  multipart.dict   1048576 15 4
fuzz_websocket       websocket.dict   262144  15 4
fuzz_http_response   http.dict        1048576 15 3
fuzz_utils           -                262144  10 2
fuzz_range           -                65536   10 2
"
export ASAN_OPTIONS="detect_leaks=0:allocator_may_return_null=1:handle_abort=1:symbolize=1:detect_stack_use_after_return=1:strict_string_checks=1:check_initialization_order=1"
export UBSAN_OPTIONS="print_stacktrace=1:halt_on_error=1:suppressions=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/ubsan.supp"
