#!/usr/bin/env bash
set -e

for i in 1 2 3 4 5 6; do
    echo "=========================================="
    /tmp/test_load_wave_samples $i
    echo ""
done

echo "ALL 6 TEST CASES PASSED SUCCESSFULLY!"
