# Testing Guide for Insider Threat Detection System

This document provides comprehensive information about testing the Insider Threat Detection System.

## Test Structure

The test suite is organized into several modules:

### Core Test Modules

1. **`test_client.py`** - Tests for client-side functionality
   - User registration and authentication
   - System information collection
   - Network activity monitoring
   - USB event detection
   - File operations
   - Web activity collection

2. **`test_server.py`** - Tests for server-side functionality
   - Admin authentication
   - User management (add, accept, remove)
   - Activity logging and reporting
   - Anomaly detection
   - File sharing operations
   - Database operations

3. **`test_anomaly_detection.py`** - Tests for ML-based anomaly detection
   - Feature extraction
   - Model loading and prediction
   - Threshold detection
   - Anomaly scoring
   - Pattern recognition

4. **`test_integration.py`** - Integration tests
   - Client-server communication
   - End-to-end workflows
   - Real-time updates
   - System resilience
   - Performance under load

5. **`test_security.py`** - Security-focused tests
   - Authentication and authorization
   - Input validation and sanitization
   - SQL injection prevention
   - Session management
   - Data encryption
   - Access control

6. **`test_performance.py`** - Performance and scalability tests
   - Response time measurements
   - Concurrent user handling
   - Memory usage patterns
   - Database performance
   - Scalability testing

## Running Tests

### Prerequisites

Install required testing dependencies:

```bash
pip install unittest2 coverage mock
```

### Running All Tests

```bash
# Run all tests
python tests/run_tests.py

# Run with coverage report
python tests/run_tests.py coverage
```

### Running Specific Test Modules

```bash
# Run client tests only
python tests/run_tests.py test_client

# Run server tests only
python tests/run_tests.py test_server

# Run security tests only
python tests/run_tests.py test_security
```

### Running Individual Test Cases

```bash
# Run specific test class
python -m unittest tests.test_client.TestClientFunctions

# Run specific test method
python -m unittest tests.test_client.TestClientFunctions.test_validate_password_success
```

## Test Categories

### Unit Tests
- Test individual functions and methods
- Mock external dependencies
- Fast execution
- High code coverage

### Integration Tests
- Test component interactions
- Use real or realistic data
- Test complete workflows
- Verify system behavior

### Performance Tests
- Measure response times
- Test under load
- Memory usage validation
- Scalability verification

### Security Tests
- Authentication testing
- Input validation
- Access control verification
- Data protection testing

## Test Data and Fixtures

### Mock Data
Tests use mock data to simulate:
- User accounts and credentials
- System logs and metrics
- Network activity
- USB events
- File operations
- Web browsing history

### Test Databases
- Temporary SQLite databases for testing
- Isolated test data
- Automatic cleanup after tests

### Test Files
- Temporary files for file operation tests
- Automatic cleanup
- Safe test environments

## Coverage Requirements

### Target Coverage Levels
- **Unit Tests**: 90%+ line coverage
- **Integration Tests**: 80%+ feature coverage
- **Security Tests**: 100% critical path coverage

### Coverage Reports
```bash
# Generate HTML coverage report
python tests/run_tests.py coverage

# View coverage report
open htmlcov/index.html
```

## Continuous Integration

### Automated Testing
Tests should be run automatically on:
- Code commits
- Pull requests
- Scheduled intervals
- Before deployments

### Test Environment
- Isolated test environment
- Clean database state
- Consistent test data
- Reproducible results

## Test Best Practices

### Writing Tests
1. **Clear Test Names**: Use descriptive test method names
2. **Single Responsibility**: Each test should test one thing
3. **Arrange-Act-Assert**: Structure tests clearly
4. **Mock External Dependencies**: Isolate units under test
5. **Clean Up**: Ensure tests clean up after themselves

### Test Data Management
1. **Use Fixtures**: Consistent test data setup
2. **Isolate Tests**: Tests should not depend on each other
3. **Clean State**: Each test starts with a clean state
4. **Realistic Data**: Use realistic but safe test data

### Performance Testing
1. **Set Baselines**: Establish performance baselines
2. **Monitor Trends**: Track performance over time
3. **Load Testing**: Test under realistic load
4. **Resource Monitoring**: Monitor CPU, memory, disk usage

## Security Testing Guidelines

### Authentication Testing
- Test valid and invalid credentials
- Test session management
- Test password policies
- Test account lockout mechanisms

### Input Validation Testing
- Test SQL injection attempts
- Test XSS prevention
- Test file upload security
- Test parameter tampering

### Access Control Testing
- Test role-based permissions
- Test unauthorized access attempts
- Test privilege escalation
- Test data access controls

## Troubleshooting Tests

### Common Issues

1. **Import Errors**
   ```bash
   # Ensure Python path is set correctly
   export PYTHONPATH="${PYTHONPATH}:$(pwd)"
   ```

2. **Database Errors**
   ```bash
   # Clean up test databases
   rm -f test_*.db
   ```

3. **Permission Errors**
   ```bash
   # Ensure test files are writable
   chmod 755 tests/
   ```

4. **Mock Issues**
   - Verify mock patches are applied correctly
   - Check mock return values
   - Ensure mocks are reset between tests

### Debugging Tests
```bash
# Run tests with verbose output
python -m unittest tests.test_client -v

# Run single test with debugging
python -m pdb -m unittest tests.test_client.TestClientFunctions.test_validate_password_success
```

## Test Metrics and Reporting

### Key Metrics
- **Test Coverage**: Percentage of code covered by tests
- **Test Success Rate**: Percentage of tests passing
- **Test Execution Time**: Time taken to run test suite
- **Defect Detection Rate**: Number of bugs found by tests

### Reporting
- Generate test reports in multiple formats
- Track test metrics over time
- Monitor test stability
- Report test results to stakeholders

## Contributing to Tests

### Adding New Tests
1. Follow existing test patterns
2. Add tests for new features
3. Update tests for bug fixes
4. Maintain test documentation

### Test Review Process
1. Code review for test changes
2. Verify test coverage
3. Check test quality
4. Validate test effectiveness

## Test Environment Setup

### Development Environment
```bash
# Install development dependencies
pip install -r requirements.txt
pip install -r requirements-dev.txt

# Set up test database
python setup_test_db.py

# Run initial test suite
python tests/run_tests.py
```

### CI/CD Environment
```yaml
# Example GitHub Actions workflow
name: Test Suite
on: [push, pull_request]
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
      - name: Set up Python
        uses: actions/setup-python@v2
        with:
          python-version: 3.8
      - name: Install dependencies
        run: pip install -r requirements.txt
      - name: Run tests
        run: python tests/run_tests.py coverage
```

This comprehensive testing framework ensures the reliability, security, and performance of the Insider Threat Detection System.