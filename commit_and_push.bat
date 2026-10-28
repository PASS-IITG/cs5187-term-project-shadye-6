@echo off
echo ========================================================
echo  Committing and Pushing Adaptive Hybrid Fuzzer to fuzzer-gltf
echo ========================================================

cd /d "%~dp0"
git status
git add .
git commit -m "feat(adaptive): implement Discounted-UCB mutation scheduler and conservative saturation monitor

- Add 64-bit FNV-1a content hash utility shared across C++ and Python (fuzz/hash_util.hpp)
- Implement Mutation Operator Registry and Discounted-UCB dynamic scheduler (fuzz/mutation_scheduler.hpp/cpp)
- Implement in-memory FIFO provenance ledger with single-consumption replay safety (fuzz/mutation_telemetry.hpp/cpp)
- Integrate dynamic operator dispatch and thread-local stage flag recorder (fuzz/custom_mutator.cpp, deep_fuzzer.cpp)
- Add conservative 6-state saturation monitor with plateau recovery sequence (scripts/saturation_monitor.py)
- Add epoch-based campaign manager with restart-resilient execution accounting (scripts/campaign_manager.py)
- Add C++ unit test suite (tests/scheduler_tests.cpp) and Python test suite (scripts/test_adaptive_fuzzer.py)
- Update README.md and src/README.md with complete architecture, mathematical formulas, and run instructions"

git push origin fuzzer-gltf

echo.
echo Done!
pause

