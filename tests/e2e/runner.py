"""
Unified E2E Test Suite Runner for Bharat Forensic Suite.
Supports selective execution by tier (1, 2, 3, 4, or all) and provides
detailed forensic test execution metrics and statutory compliance reporting.

Usage:
    python tests/e2e/runner.py --tier all
    python tests/e2e/runner.py --tier 1
    python tests/e2e/runner.py --tier 2
    python tests/e2e/runner.py --tier 3
    python tests/e2e/runner.py --tier 4
    python tests/e2e/runner.py --tier all --verbose
"""

from __future__ import annotations

import argparse
import importlib
import os
import sys
import time
import unittest
from pathlib import Path
from typing import Dict, List, Tuple

# Ensure project root is on sys.path
_root = Path(__file__).resolve().parent.parent.parent
if str(_root) not in sys.path:
    sys.path.insert(0, str(_root))

import tests.e2e.env_setup  # noqa: F401 - Enforces sandbox and path sanitization


TIER_MODULE_MAP = {
    "1": [
        "tests.e2e.test_tier1_ingestion",
        "tests.e2e.test_tier1_sqlite_recovery",
        "tests.e2e.test_tier1_upi_parsers",
        "tests.e2e.test_tier1_banking",
        "tests.e2e.test_tier1_truecaller",
        "tests.e2e.test_tier1_chats",
        "tests.e2e.test_tier1_crypto",
        "tests.e2e.test_tier1_ui_bridge",
    ],
    "2": [
        "tests.e2e.test_tier2_boundary_corner",
    ],
    "3": [
        "tests.e2e.test_tier3_cross_feature",
    ],
    "4": [
        "tests.e2e.test_tier4_real_world",
    ],
}


def run_test_module(module_name: str, verbosity: int = 1) -> Tuple[int, int, int, int, float, list]:
    """Runs a single test module, returning (run, passed, failed, errors, elapsed_sec, failure_details)."""
    module = importlib.import_module(module_name)
    loader = unittest.TestLoader()
    suite = loader.loadTestsFromModule(module)

    start_time = time.perf_counter()
    stream = sys.stderr if verbosity > 1 else open(os.devnull, "w")
    runner = unittest.TextTestRunner(stream=stream, verbosity=verbosity)
    result = runner.run(suite)
    elapsed = time.perf_counter() - start_time

    if verbosity <= 1:
        stream.close()

    total_run = result.testsRun
    failures = len(result.failures)
    errors = len(result.errors)
    passed = total_run - (failures + errors)

    failure_details = []
    for test, trace in result.failures:
        failure_details.append((str(test), "FAILURE", trace))
    for test, trace in result.errors:
        failure_details.append((str(test), "ERROR", trace))

    return total_run, passed, failures, errors, elapsed, failure_details


def main():
    parser = argparse.ArgumentParser(description="Bharat Forensic Suite - E2E Test Suite Runner")
    parser.add_argument(
        "--tier",
        choices=["1", "2", "3", "4", "all"],
        default="all",
        help="Select which test tier to execute (default: all)",
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Enable verbose output during test execution",
    )
    args = parser.parse_args()

    selected_tiers = ["1", "2", "3", "4"] if args.tier == "all" else [args.tier]
    verbosity = 2 if args.verbose else 1

    print("=" * 86)
    print(" BHARAT FORENSIC SUITE - COMPREHENSIVE E2E VERIFICATION TEST SUITE ")
    print(" Statutory Mandate: Section 63 BSA 2023 & Section 230 BNSS Compliant ")
    print("=" * 86)
    print(f"Selected Tiers: {', '.join('Tier ' + t for t in selected_tiers)}")
    print("-" * 86)

    table_rows = []
    total_all_run = 0
    total_all_passed = 0
    total_all_failed = 0
    total_all_errors = 0
    total_suite_time = 0.0
    all_failures = []

    for tier in selected_tiers:
        modules = TIER_MODULE_MAP[tier]
        for mod in modules:
            mod_display = mod.split(".")[-1]
            try:
                run, passed, failures, errors, elapsed, fail_details = run_test_module(mod, verbosity)
                total_all_run += run
                total_all_passed += passed
                total_all_failed += failures
                total_all_errors += errors
                total_suite_time += elapsed
                if fail_details:
                    all_failures.extend(fail_details)

                status = "PASS" if failures == 0 and errors == 0 else "FAIL"
                table_rows.append((f"Tier {tier}", mod_display, run, passed, failures, errors, f"{elapsed:.3f}s", status))
                if verbosity <= 1:
                    print(f"[{status}] Tier {tier} :: {mod_display:<35} -> {passed}/{run} passed in {elapsed:.3f}s")
            except Exception as exc:
                table_rows.append((f"Tier {tier}", mod_display, 0, 0, 0, 1, "0.000s", "CRASH"))
                all_failures.append((mod, "MODULE_CRASH", str(exc)))
                total_all_errors += 1
                print(f"[CRASH] Tier {tier} :: {mod_display} -> Exception: {exc}")

    print("\n" + "=" * 86)
    print(f"{'Tier':<8} {'Module Name':<38} {'Run':<6} {'Pass':<6} {'Fail':<6} {'Time':<10} {'Status':<6}")
    print("-" * 86)
    for tier_lbl, mod_name, run, passed, failures, errors, time_str, status in table_rows:
        fail_err = failures + errors
        print(f"{tier_lbl:<8} {mod_name:<38} {run:<6} {passed:<6} {fail_err:<6} {time_str:<10} {status:<6}")
    print("-" * 86)
    print(f"{'TOTAL':<8} {'All Evaluated Suites':<38} {total_all_run:<6} {total_all_passed:<6} {total_all_failed + total_all_errors:<6} {total_suite_time:.3f}s")
    print("=" * 86)

    if all_failures:
        print("\nFAILURE / ERROR DETAILS:")
        for test_name, kind, trace in all_failures:
            print(f"\n--- {kind}: {test_name} ---")
            print(trace)
        print("=" * 86)
        sys.exit(1)
    else:
        print("\nALL E2E FORENSIC SUITES PASSED PERFECTLY (100% SUCCESSFUL).")
        print("Ready for Court Production Certification under Section 63 BSA 2023.")
        print("=" * 86)
        sys.exit(0)


if __name__ == "__main__":
    main()
