#!/usr/bin/env bash
# ══════════════════════════════════════════════════════════════════════
# test_models.sh — Verify model availability via OAuth
#
# Uses Rust integration test that goes through the real provider
# pipeline (AuthService → token decryption → OAuth refresh → API call).
#
# Usage:
#   ./dev/test_models.sh              # test all models + profile rotation
#   ./dev/test_models.sh models       # test model availability only
#   ./dev/test_models.sh profiles     # test profile rotation only
# ══════════════════════════════════════════════════════════════════════
set -euo pipefail

cd "$(dirname "$0")/.."

CYAN='\033[0;36m'
NC='\033[0m'
info() { echo -e "${CYAN}▸${NC} $1"; }

case "${1:-all}" in
    models)
        info "Testing Gemini model availability via OAuth..."
        cargo test --test gemini_model_availability gemini_models_available_via_oauth \
            -- --ignored --nocapture
        ;;
    profiles)
        info "Testing Gemini profile rotation (both profiles)..."
        cargo test --test gemini_model_availability gemini_profiles_rotation_live \
            -- --ignored --nocapture
        ;;
    all)
        info "Testing Gemini models + profile rotation via OAuth..."
        cargo test --test gemini_model_availability \
            -- --ignored --nocapture
        ;;
    *)
        echo "Usage: $0 [models|profiles|all]"
        exit 1
        ;;
esac
