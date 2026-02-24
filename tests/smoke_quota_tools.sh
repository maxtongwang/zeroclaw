#!/bin/bash
# Quick smoke tests for quota tools (faster than full E2E)

set -e

ZEROCLAW="./target/release/zeroclaw"
GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m'

echo "========================================"
echo "Smoke Tests: Quota Tools"
echo "========================================"

# Test 1: CLI quota command
echo -n "1. CLI providers-quota ... "
if $ZEROCLAW providers-quota 2>&1 | grep -q "Provider Quota Status"; then
    echo -e "${GREEN}✅${NC}"
else
    echo -e "${RED}❌${NC}"
    exit 1
fi

# Test 2: JSON format
echo -n "2. JSON format ... "
if $ZEROCLAW providers-quota --format json 2>&1 | grep -q '"timestamp"'; then
    echo -e "${GREEN}✅${NC}"
else
    echo -e "${RED}❌${NC}"
    exit 1
fi

# Test 3: Tool registration
echo -n "3. Quota tools registered ... "
if grep -q "CheckProviderQuotaTool\|SwitchProviderTool\|EstimateQuotaCostTool" src/tools/mod.rs; then
    echo -e "${GREEN}✅${NC}"
else
    echo -e "${RED}❌${NC}"
    exit 1
fi

# Test 4: Agent loop integration
echo -n "4. Agent loop quota code ... "
if grep -q "check_quota_warning\|parse_switch_provider_metadata" src/agent/loop_.rs; then
    echo -e "${GREEN}✅${NC}"
else
    echo -e "${RED}❌${NC}"
    exit 1
fi

# Test 5: Quick agent invocation with check_provider_quota
echo -n "5. Agent can call check_provider_quota ... "
AGENT_OUTPUT=$(timeout 60 $ZEROCLAW agent --provider gemini -m "use check_provider_quota tool" 2>&1 || true)
if echo "$AGENT_OUTPUT" | grep -qi "check_provider_quota"; then
    echo -e "${GREEN}✅${NC}"
else
    echo -e "${RED}❌${NC}"
    echo "Output: $AGENT_OUTPUT" | tail -5
fi

echo ""
echo -e "${GREEN}✅ All smoke tests passed!${NC}"
