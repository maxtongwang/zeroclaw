#!/bin/bash
# Quick live model test for quota tools

ZEROCLAW="./target/release/zeroclaw"

echo "=== Live Model Test 1: check_provider_quota ==="
timeout 60 $ZEROCLAW agent --provider gemini -m "Use check_provider_quota tool and tell me which providers are available" 2>&1 | grep -E "(check_provider_quota|Available|provider)" | head -20

echo ""
echo "=== Live Model Test 2: estimate_quota_cost ==="
timeout 60 $ZEROCLAW agent --provider gemini -m "Use estimate_quota_cost tool for operation=tool_call with estimated_tokens=500" 2>&1 | grep -E "(estimate_quota_cost|Estimated|tokens|cost)" | head -20

echo ""
echo "=== Live Model Test 3: switch_provider ==="
timeout 60 $ZEROCLAW agent --provider gemini -m "Use switch_provider tool to switch to anthropic" 2>&1 | grep -E "(switch_provider|Switching|switch|anthropic)" | head -20

echo ""
echo "=== Done ==="
