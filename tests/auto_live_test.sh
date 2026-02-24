#!/bin/bash
# Automated live model tests (full autonomy, no approval prompts)

ZEROCLAW="./target/release/zeroclaw"
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo "========================================"
echo "Automated Live Model Tests"
echo "Using: full autonomy mode"
echo "========================================"
echo ""

TEST_COUNT=0
PASS_COUNT=0

run_auto_test() {
    local name="$1"
    local message="$2"
    local expected="$3"

    ((TEST_COUNT++))
    echo -n "[$TEST_COUNT] $name ... "

    OUTPUT=$(timeout 90 bash -c "yes A | $ZEROCLAW agent --provider gemini -m '$message' 2>&1" || true)

    if echo "$OUTPUT" | grep -qi "$expected"; then
        echo -e "${GREEN}✅ PASS${NC}"
        ((PASS_COUNT++))
        echo "$OUTPUT" | grep -i "$expected" | head -3 | sed 's/^/    /'
    else
        echo -e "${RED}❌ FAIL${NC}"
        echo "Expected pattern: $expected"
        echo "Last 10 lines:"
        echo "$OUTPUT" | tail -10 | sed 's/^/    /'
    fi
    echo ""
}

# Test 1: check_provider_quota tool
run_auto_test \
    "check_provider_quota execution" \
    "Use check_provider_quota tool to check quota status" \
    "check_provider_quota"

# Test 2: estimate_quota_cost tool
run_auto_test \
    "estimate_quota_cost execution" \
    "Use estimate_quota_cost tool for operation=tool_call with estimated_tokens=1000" \
    "estimate_quota_cost"

# Test 3: switch_provider tool
run_auto_test \
    "switch_provider execution" \
    "Use switch_provider tool to switch to anthropic provider" \
    "switch_provider"

# Test 4: Multiple tools in sequence
run_auto_test \
    "Sequential tool execution" \
    "First use check_provider_quota, then estimate_quota_cost for tool_call with 500 tokens" \
    "check_provider_quota"

# Test 5: Simple query to verify basic functionality
run_auto_test \
    "Basic model response" \
    "What is 2+2? Answer with just the number" \
    "4"

echo "========================================"
echo "Results: $PASS_COUNT/$TEST_COUNT tests passed"
echo "========================================"

if [ $PASS_COUNT -eq $TEST_COUNT ]; then
    echo -e "${GREEN}✅ All tests passed!${NC}"
    exit 0
else
    echo -e "${YELLOW}⚠️  Some tests failed or timed out${NC}"
    exit 1
fi
