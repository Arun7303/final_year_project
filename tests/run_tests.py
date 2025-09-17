#!/usr/bin/env python3
"""
Test runner script for the Insider Threat Detection System
"""

import unittest
import sys
import os
import time
from io import StringIO

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

def run_test_suite():
    """Run the complete test suite."""
    print("=" * 70)
    print("INSIDER THREAT DETECTION SYSTEM - TEST SUITE")
    print("=" * 70)
    
    # Discover and run all tests
    loader = unittest.TestLoader()
    start_dir = os.path.dirname(os.path.abspath(__file__))
    suite = loader.discover(start_dir, pattern='test_*.py')
    
    # Create a test runner with detailed output
    stream = StringIO()
    runner = unittest.TextTestRunner(
        stream=stream,
        verbosity=2,
        buffer=True,
        failfast=False
    )
    
    print(f"Discovered {suite.countTestCases()} test cases")
    print("-" * 70)
    
    start_time = time.time()
    result = runner.run(suite)
    end_time = time.time()
    
    # Print results
    output = stream.getvalue()
    print(output)
    
    print("-" * 70)
    print(f"Tests run: {result.testsRun}")
    print(f"Failures: {len(result.failures)}")
    print(f"Errors: {len(result.errors)}")
    print(f"Skipped: {len(result.skipped) if hasattr(result, 'skipped') else 0}")
    print(f"Time taken: {end_time - start_time:.2f} seconds")
    
    if result.failures:
        print("\nFAILURES:")
        for test, traceback in result.failures:
            print(f"- {test}: {traceback}")
    
    if result.errors:
        print("\nERRORS:")
        for test, traceback in result.errors:
            print(f"- {test}: {traceback}")
    
    print("-" * 70)
    
    if result.wasSuccessful():
        print("✅ ALL TESTS PASSED!")
        return 0
    else:
        print("❌ SOME TESTS FAILED!")
        return 1

def run_specific_test(test_module):
    """Run a specific test module."""
    print(f"Running tests from {test_module}")
    print("-" * 50)
    
    loader = unittest.TestLoader()
    suite = loader.loadTestsFromName(test_module)
    
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    
    return 0 if result.wasSuccessful() else 1

def run_coverage_report():
    """Run tests with coverage report."""
    try:
        import coverage
        
        print("Running tests with coverage analysis...")
        print("-" * 50)
        
        # Start coverage
        cov = coverage.Coverage()
        cov.start()
        
        # Run tests
        result_code = run_test_suite()
        
        # Stop coverage and generate report
        cov.stop()
        cov.save()
        
        print("\nCOVERAGE REPORT:")
        print("-" * 30)
        cov.report()
        
        # Generate HTML report
        cov.html_report(directory='htmlcov')
        print("\nHTML coverage report generated in 'htmlcov' directory")
        
        return result_code
        
    except ImportError:
        print("Coverage module not installed. Install with: pip install coverage")
        print("Running tests without coverage...")
        return run_test_suite()

def main():
    """Main test runner function."""
    if len(sys.argv) > 1:
        command = sys.argv[1]
        
        if command == "coverage":
            return run_coverage_report()
        elif command.startswith("test_"):
            return run_specific_test(command)
        else:
            print(f"Unknown command: {command}")
            print("Usage:")
            print("  python run_tests.py                 # Run all tests")
            print("  python run_tests.py coverage        # Run with coverage")
            print("  python run_tests.py test_client     # Run specific test module")
            return 1
    else:
        return run_test_suite()

if __name__ == "__main__":
    sys.exit(main())