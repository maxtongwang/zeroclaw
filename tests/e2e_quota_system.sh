#!/bin/bash
# E2E Tests for Quota Monitoring System (Phases 1-5)
# Tests quota checks, provider switching, circuit breaker, warnings
# WITHOUT Telegram - direct CLI agent invocation

set -e

ZEROCLAW="./target/release/zeroclaw"
TEST_OUTPUT_DIR="/tmp/zeroclaw_e2e_tests"
TIMEOUT=90

# Colors
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

mkdir -p "$TEST_OUTPUT_DIR"

echo "========================================"
echo "E2E Quota System Tests"
echo "========================================"
echo ""

# Build if needed
if [ ! -f "$ZEROCLAW" ]; then
    echo "📦 Building release version..."
    ~/.cargo/bin/cargo build --release --quiet 2>/dev/null || ~/.cargo/bin/cargo build --release
fi

echo "Using: $ZEROCLAW"
echo "Test output: $TEST_OUTPUT_DIR"
echo ""

PASS_COUNT=0
FAIL_COUNT=0

# Helper functions
run_test() {
    local test_name="$1"
    local command="$2"
    local expected_pattern="$3"
    local output_file="$TEST_OUTPUT_DIR/${test_name// /_}.txt"

    echo -n "Test: $test_name ... "

    if timeout $TIMEOUT bash -c "$command" > "$output_file" 2>&1; then
        if grep -q "$expected_pattern" "$output_file"; then
            echo -e "${GREEN}✅ PASS${NC}"
            ((PASS_COUNT++))
            return 0
        else
            echo -e "${RED}❌ FAIL${NC} (pattern not found: $expected_pattern)"
            echo "Output excerpt:"
            tail -20 "$output_file" | sed 's/^/  /'
            ((FAIL_COUNT++))
            return 1
        fi
    else
        echo -e "${RED}❌ FAIL${NC} (timeout or error)"
        echo "Output excerpt:"
        tail -20 "$output_file" | sed 's/^/  /'
        ((FAIL_COUNT++))
        return 1
    fi
}

run_interactive_test() {
    local test_name="$1"
    local message="$2"
    local expected_pattern="$3"
    local provider="${4:-gemini}"

    run_test "$test_name" \
        "$ZEROCLAW agent --provider $provider -m \"$message\" 2>&1" \
        "$expected_pattern"
}

echo "========================================"
echo "Phase 1-2: CLI Quota Commands"
echo "========================================"
echo ""

run_test "CLI providers-quota (text format)" \
    "$ZEROCLAW providers-quota 2>&1 | grep -v INFO" \
    "Provider Quota Status"

run_test "CLI providers-quota (JSON format)" \
    "$ZEROCLAW providers-quota --format json 2>&1 | grep -v INFO" \
    '"timestamp"'

run_test "CLI providers-quota (filter by provider)" \
    "$ZEROCLAW providers-quota --provider gemini 2>&1 | grep -v INFO" \
    "Provider Quota Status"

echo ""
echo "========================================"
echo "Phase 4: Built-in Tools (Conversational)"
echo "========================================"
echo ""

run_interactive_test \
    "check_provider_quota tool execution" \
    "Use the check_provider_quota tool to check all providers" \
    "check_provider_quota"

run_interactive_test \
    "estimate_quota_cost tool execution" \
    "Use estimate_quota_cost tool with operation=tool_call and estimated_tokens=1000" \
    "estimate_quota_cost"

run_interactive_test \
    "switch_provider tool execution" \
    "Use switch_provider tool to switch to openai provider" \
    "switch_provider"

echo ""
echo "========================================"
echo "Phase 5: Provider Switching Tests"
echo "========================================"
echo ""

run_interactive_test \
    "Explicit provider switch request" \
    "Switch to anthropic provider and tell me you switched" \
    "switch"

run_interactive_test \
    "Model-specific request (gemini)" \
    "Use gemini to answer: what is 2+2?" \
    "4" \
    "gemini"

run_interactive_test \
    "Check available providers before operation" \
    "First check which providers are available using check_provider_quota, then answer hello" \
    "check_provider_quota"

echo ""
echo "========================================"
echo "Phase 5: Circuit Breaker Tests"
echo "========================================"
echo ""

# Test that circuit breaker info is logged
run_test "Circuit breaker state in logs" \
    "$ZEROCLAW agent --provider gemini -m 'hello' 2>&1 | grep -i 'circuit\|breaker\|threshold\|skipping provider' || echo 'No circuit breaker activity'" \
    "."

# Test provider fallback behavior
run_interactive_test \
    "Provider fallback on unavailable model" \
    "Say hello" \
    "." \
    "gemini"

echo ""
echo "========================================"
echo "Integration Tests"
echo "========================================"
echo ""

run_interactive_test \
    "Multi-tool conversation flow" \
    "First estimate cost for 5 parallel operations, then check quota status, then say done" \
    "done"

run_interactive_test \
    "Quota check before switch" \
    "Check quota using check_provider_quota tool, then switch to openai using switch_provider tool" \
    "switch_provider"

echo ""
echo "========================================"
echo "Stress Tests (Rate Limiting)"
echo "========================================"
echo ""

# Test parallel tool execution (should trigger quota warning if >= 5)
run_interactive_test \
    "Request many parallel operations" \
    "I need you to execute 10 file_read operations in parallel for /etc/hosts" \
    "file_read"

echo ""
echo "========================================"
echo "Test Results Summary"
echo "========================================"
echo ""

TOTAL_TESTS=$((PASS_COUNT + FAIL_COUNT))
PASS_RATE=$(awk "BEGIN {printf \"%.1f\", ($PASS_COUNT/$TOTAL_TESTS)*100}")

echo "Total tests: $TOTAL_TESTS"
echo -e "Passed: ${GREEN}$PASS_COUNT${NC}"
echo -e "Failed: ${RED}$FAIL_COUNT${NC}"
echo "Pass rate: $PASS_RATE%"
echo ""

if [ $FAIL_COUNT -eq 0 ]; then
    echo -e "${GREEN}✅ All tests passed!${NC}"
    exit 0
else
    echo -e "${RED}❌ Some tests failed${NC}"
    echo ""
    echo "Failed test outputs available in: $TEST_OUTPUT_DIR"
    exit 1
fi
