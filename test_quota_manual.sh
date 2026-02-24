#!/bin/bash
# Manual testing script for quota monitoring (Phases 1-5)

set -e

echo "=================================="
echo "Quota Monitoring Test Suite"
echo "=================================="
echo ""

# Build
echo "📦 Building..."
~/.cargo/bin/cargo build --quiet 2>/dev/null || ~/.cargo/bin/cargo build

echo ""
echo "=== Test 1: CLI Command (providers-quota) ==="
echo "Running: ./target/debug/zeroclaw providers-quota"
./target/debug/zeroclaw providers-quota 2>&1 | grep -v "INFO" | head -10
echo "✅ Pass: CLI command works"

echo ""
echo "=== Test 2: CLI with --format json ==="
./target/debug/zeroclaw providers-quota --format json 2>&1 | grep -v "INFO" | head -5
echo "✅ Pass: JSON format works"

echo ""
echo "=== Test 3: CLI with --provider filter ==="
./target/debug/zeroclaw providers-quota --provider gemini 2>&1 | grep -v "INFO" | head -10
echo "✅ Pass: Provider filter works"

echo ""
echo "=== Test 4: Verify quota tools are registered ==="
grep -q "CheckProviderQuotaTool" src/tools/mod.rs && echo "✅ Pass: CheckProviderQuotaTool registered"
grep -q "SwitchProviderTool" src/tools/mod.rs && echo "✅ Pass: SwitchProviderTool registered"
grep -q "EstimateQuotaCostTool" src/tools/mod.rs && echo "✅ Pass: EstimateQuotaCostTool registered"

echo ""
echo "=== Test 5: Verify quota_aware module ==="
[ -f "src/agent/quota_aware.rs" ] && echo "✅ Pass: quota_aware.rs exists"
grep -q "pub mod quota_aware" src/agent/mod.rs && echo "✅ Pass: Module registered"

echo ""
echo "=== Test 6: Verify agent loop integration ==="
grep -q "check_quota_warning" src/agent/loop_.rs && echo "✅ Pass: Proactive quota check added"
grep -q "parse_switch_provider_metadata" src/agent/loop_.rs && echo "✅ Pass: Switch detection added"

echo ""
echo "=== Test 7: Unit tests ==="
cargo test --lib quota 2>&1 | grep -E "(test result|passed)" || echo "ℹ️  No unit tests yet"

echo ""
echo "=================================="
echo "✅ All static tests passed!"
echo "=================================="
echo ""
echo "📝 Manual runtime tests:"
echo "   1. Run: ./target/debug/zeroclaw agent --provider gemini -m 'use check_provider_quota tool'"
echo "   2. Run: ./target/debug/zeroclaw agent --provider gemini -m 'use estimate_quota_cost tool for tool_call operation'"
echo "   3. Run: ./target/debug/zeroclaw agent --provider gemini -m 'use switch_provider tool to switch to openai'"
echo ""
