#!/bin/bash
# ZeroClaw Telegram Reader Skill Test Suite
# Tests the telegram-reader skill functionality

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Test counters
TOTAL_TESTS=0
PASSED_TESTS=0
FAILED_TESTS=0

# Helper functions
print_header() {
    echo -e "\n${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${BLUE}$1${NC}"
    echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}\n"
}

print_test() {
    TOTAL_TESTS=$((TOTAL_TESTS + 1))
    echo -e "${YELLOW}Test $TOTAL_TESTS:${NC} $1"
}

pass() {
    PASSED_TESTS=$((PASSED_TESTS + 1))
    echo -e "${GREEN}✓ PASS:${NC} $1\n"
}

fail() {
    FAILED_TESTS=$((FAILED_TESTS + 1))
    echo -e "${RED}✗ FAIL:${NC} $1\n"
}

warn() {
    echo -e "${YELLOW}⚠ WARNING:${NC} $1\n"
}

# Banner
clear
cat << "EOF"
    ⚡⚡⚡⚡⚡⚡⚡⚡⚡⚡⚡⚡⚡⚡⚡⚡⚡⚡⚡⚡⚡⚡⚡⚡⚡⚡⚡⚡⚡⚡

    ███████╗███████╗██████╗  ██████╗  ██████╗██╗      █████╗ ██╗    ██╗
    ╚══███╔╝██╔════╝██╔══██╗██╔═══██╗██╔════╝██║     ██╔══██╗██║    ██║
      ███╔╝ █████╗  ██████╔╝██║   ██║██║     ██║     ███████║██║ █╗ ██║
     ███╔╝  ██╔══╝  ██╔══██╗██║   ██║██║     ██║     ██╔══██║██║███╗██║
    ███████╗███████╗██║  ██║╚██████╔╝╚██████╗███████╗██║  ██║╚███╔███╔╝
    ╚══════╝╚══════╝╚═╝  ╚═╝ ╚═════╝  ╚═════╝╚══════╝╚═╝  ╚═╝ ╚══╝╚══╝

    🧪 TELEGRAM READER SKILL TEST SUITE 🧪

    ⚡⚡⚡⚡⚡⚡⚡⚡⚡⚡⚡⚡⚡⚡⚡⚡⚡⚡⚡⚡⚡⚡⚡⚡⚡⚡⚡⚡⚡⚡
EOF

echo -e "\n${BLUE}Started at:${NC} $(date)"
echo -e "${BLUE}Working directory:${NC} $(pwd)\n"

SKILL_DIR="$HOME/.zeroclaw/workspace/skills/telegram-reader"
ZEROCLAW_BIN="$PWD/target/release/zeroclaw"

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Phase 1: Prerequisites
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

print_header "Phase 1: Prerequisites"

# Test 1: Python available
print_test "Python 3 availability"
if command -v python3 &>/dev/null; then
    PYTHON_VERSION=$(python3 --version | awk '{print $2}')
    pass "Python 3 found: $PYTHON_VERSION"
else
    fail "Python 3 not found"
    exit 1
fi

# Test 2: telethon installed
print_test "telethon library"
if python3 -c "import telethon" 2>/dev/null; then
    TELETHON_VERSION=$(python3 -c "import telethon; print(telethon.__version__)")
    pass "telethon installed: $TELETHON_VERSION"
else
    fail "telethon not installed - run: pip3 install telethon --user"
    exit 1
fi

# Test 3: Skill directory exists
print_test "Skill directory structure"
if [ -d "$SKILL_DIR" ]; then
    pass "Skill directory exists: $SKILL_DIR"
else
    fail "Skill directory not found: $SKILL_DIR"
    exit 1
fi

# Test 4: SKILL.toml exists
print_test "SKILL.toml manifest"
if [ -f "$SKILL_DIR/SKILL.toml" ]; then
    pass "SKILL.toml found"
else
    fail "SKILL.toml not found"
    exit 1
fi

# Test 5: Python script exists
print_test "telegram_reader.py script"
if [ -f "$SKILL_DIR/scripts/telegram_reader.py" ]; then
    pass "telegram_reader.py found"
else
    fail "telegram_reader.py not found"
    exit 1
fi

# Test 6: Python syntax
print_test "Python script syntax"
if python3 -m py_compile "$SKILL_DIR/scripts/telegram_reader.py" 2>/dev/null; then
    pass "Python syntax valid"
else
    fail "Python syntax error"
fi

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Phase 2: Configuration
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

print_header "Phase 2: Configuration"

# Test 7: .env file exists
print_test ".env file"
if [ -f ".env" ]; then
    pass ".env file found"
else
    warn ".env file not found - credentials may not be loaded"
fi

# Test 8: Telegram credentials
print_test "Telegram API credentials"
source .env 2>/dev/null || true
if [ -n "$TELEGRAM_API_ID" ] && [ -n "$TELEGRAM_API_HASH" ]; then
    pass "Telegram credentials configured"
    echo -e "   API_ID: ${TELEGRAM_API_ID}"
    echo -e "   API_HASH: ${TELEGRAM_API_HASH:0:8}..."
    echo -e "   PHONE: ${TELEGRAM_PHONE:-'(not set)'}"
else
    fail "Telegram credentials not set in .env"
    echo "   Add to .env:"
    echo "   TELEGRAM_API_ID=your_id"
    echo "   TELEGRAM_API_HASH=your_hash"
    echo "   TELEGRAM_PHONE=+66..."
    exit 1
fi

# Test 9: Session file
print_test "Telegram session file"
if [ -f "$SKILL_DIR/.session/zverozabr_session.session" ]; then
    SESSION_SIZE=$(stat -f%z "$SKILL_DIR/.session/zverozabr_session.session" 2>/dev/null || stat -c%s "$SKILL_DIR/.session/zverozabr_session.session")
    if [ $SESSION_SIZE -gt 1000 ]; then
        pass "Valid session file found (${SESSION_SIZE} bytes)"
    else
        warn "Session file too small - may be invalid"
    fi
else
    warn "Session file not found - run authenticate.py first"
fi

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Phase 3: Skill Registration
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

print_header "Phase 3: Skill Registration"

# Test 10: ZeroClaw binary
print_test "ZeroClaw binary"
if [ -f "$ZEROCLAW_BIN" ]; then
    pass "ZeroClaw found: $ZEROCLAW_BIN"
else
    warn "ZeroClaw binary not found - may need to build"
fi

# Test 11: Skill loaded
print_test "Skill registration"
if [ -f "$ZEROCLAW_BIN" ]; then
    SKILLS_OUTPUT=$($ZEROCLAW_BIN skills list 2>&1)
    if echo "$SKILLS_OUTPUT" | grep -q "telegram-reader"; then
        pass "telegram-reader skill is registered"

        # Test 12: Tool count
        print_test "Tool count verification"
        if echo "$SKILLS_OUTPUT" | grep "telegram-reader" -A 2 | grep -q "telegram_list_dialogs"; then
            TOOL_COUNT=$(echo "$SKILLS_OUTPUT" | grep "telegram-reader" -A 2 | grep "Tools:" | grep -oP '\d+' || echo "0")
            if [ "$TOOL_COUNT" == "6" ]; then
                pass "All 6 tools registered"
            else
                warn "Expected 6 tools, found $TOOL_COUNT"
            fi
        fi
    else
        fail "telegram-reader skill not found in skills list"
        echo "$SKILLS_OUTPUT"
    fi
fi

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Phase 4: Script Functionality (if authenticated)
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

print_header "Phase 4: Script Functionality"

if [ -f "$SKILL_DIR/.session/zverozabr_session.session" ]; then
    # Test 13: Help command
    print_test "Script help command"
    if python3 "$SKILL_DIR/scripts/telegram_reader.py" --help &>/dev/null; then
        pass "Help command works"
    else
        fail "Help command failed"
    fi

    # Test 14: List dialogs (timeout after 10s if interactive)
    print_test "List dialogs (may prompt if session expired)"
    echo "   Running: python3 telegram_reader.py list_dialogs --limit 3"
    echo "   (timeout in 10 seconds if stuck)"

    DIALOG_OUTPUT=$(timeout 10 python3 "$SKILL_DIR/scripts/telegram_reader.py" list_dialogs --limit 3 2>&1 || true)

    if echo "$DIALOG_OUTPUT" | grep -q '"success": true'; then
        pass "Successfully listed dialogs"
        DIALOG_COUNT=$(echo "$DIALOG_OUTPUT" | grep -oP '"count":\s*\K\d+' | head -1)
        echo "   Found $DIALOG_COUNT dialog(s)"
    elif echo "$DIALOG_OUTPUT" | grep -qi "phone\|code\|EOF"; then
        warn "Session expired or needs authentication"
        echo "   Run: python3 $SKILL_DIR/scripts/authenticate.py"
    else
        fail "Failed to list dialogs"
        echo "$DIALOG_OUTPUT" | head -5
    fi
else
    warn "Skipping functionality tests - no session file"
    echo "   To authenticate, run:"
    echo "   python3 $SKILL_DIR/scripts/authenticate.py"
fi

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Phase 5: Documentation
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

print_header "Phase 5: Documentation"

# Test 15: README
print_test "README.md exists"
if [ -f "$SKILL_DIR/README.md" ]; then
    pass "README.md found"
else
    warn "README.md not found"
fi

# Test 16: SKILL.md
print_test "SKILL.md documentation"
if [ -f "$SKILL_DIR/SKILL.md" ]; then
    pass "SKILL.md found"
else
    warn "SKILL.md not found"
fi

# Test 17: Setup instructions
print_test "Setup instructions"
if [ -f "$SKILL_DIR/SETUP_NEXT_STEPS.md" ]; then
    pass "SETUP_NEXT_STEPS.md found"
else
    warn "SETUP_NEXT_STEPS.md not found"
fi

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Test Summary
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

print_header "Test Summary"

echo -e "${BLUE}Total Tests:${NC}   $TOTAL_TESTS"
echo -e "${GREEN}Passed:${NC}        $PASSED_TESTS"
echo -e "${RED}Failed:${NC}        $FAILED_TESTS"
echo -e "${YELLOW}Warnings:${NC}      $((TOTAL_TESTS - PASSED_TESTS - FAILED_TESTS))"

PASS_RATE=$((PASSED_TESTS * 100 / TOTAL_TESTS))
echo -e "\n${BLUE}Pass Rate:${NC}     ${PASS_RATE}%"

if [ $FAILED_TESTS -eq 0 ]; then
    echo -e "\n${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${GREEN}✓ ALL TESTS PASSED! 🎉${NC}"
    echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}\n"

    echo -e "${BLUE}Next Steps:${NC}"
    echo -e "1. If session not authenticated, run:"
    echo -e "   python3 $SKILL_DIR/scripts/authenticate.py"
    echo -e ""
    echo -e "2. Test manually:"
    echo -e "   python3 $SKILL_DIR/scripts/telegram_reader.py list_dialogs --limit 5"
    echo -e ""
    echo -e "3. Test with agent:"
    echo -e "   $ZEROCLAW_BIN chat 'Show my Telegram chats'"
    echo -e ""

    exit 0
else
    echo -e "\n${RED}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${RED}✗ SOME TESTS FAILED${NC}"
    echo -e "${RED}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}\n"

    echo -e "${BLUE}Troubleshooting:${NC}"
    echo -e "1. Review failed tests above"
    echo -e "2. Check credentials in .env file"
    echo -e "3. Install missing dependencies"
    echo -e "4. Re-run this script\n"

    exit 1
fi
