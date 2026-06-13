#!/usr/bin/env bash
# =============================================================================
# RedAmon Pre-Flight Environment Check
# =============================================================================
# Run this script after creating your .env file and before
#   docker compose up -d
# to verify that no required secret still uses its default value.
# =============================================================================

set -euo pipefail

RED='\033[0;31m'
YELLOW='\033[1;33m'
GREEN='\033[0;32m'
NC='\033[0m' # No Color

ERRORS=0
WARNINGS=0

# Helper functions
check_secret() {
    local var_name="$1"
    local default_value="$2"
    local current_value="${!var_name:-}"

    if [[ -z "$current_value" ]]; then
        echo -e "${RED}ERROR${NC}: $var_name is not set (required secret)"
        ((ERRORS++))
        return
    fi

    if [[ "$current_value" == "$default_value" ]]; then
        echo -e "${RED}ERROR${NC}: $var_name is still using its default value ($default_value)"
        ((ERRORS++))
        return
    fi

    echo -e "${GREEN}OK${NC}:   $var_name is set"
}

check_min_length() {
    local var_name="$1"
    local min_len="$2"
    local current_value="${!var_name:-}"

    if [[ -z "$current_value" ]]; then
        echo -e "${RED}ERROR${NC}: $var_name is not set (required secret)"
        ((ERRORS++))
        return
    fi

    if [[ ${#current_value} -lt $min_len ]]; then
        echo -e "${YELLOW}WARN${NC}: $var_name is shorter than $min_len characters (recommended: >= 32)"
        ((WARNINGS++))
        return
    fi

    echo -e "${GREEN}OK${NC}:   $var_name meets minimum length ($min_len)"
}

check_not_default() {
    local var_name="$1"
    local default_value="$2"
    local current_value="${!var_name:-$default_value}"

    if [[ "$current_value" == "$default_value" ]]; then
        echo -e "${YELLOW}WARN${NC}: $var_name is using its default value ($default_value)"
        ((WARNINGS++))
        return
    fi

    echo -e "${GREEN}OK${NC}:   $var_name is customized"
}

# ------------------------------------------------------------------------------
# Load .env if present
# ------------------------------------------------------------------------------
if [[ -f .env ]]; then
    # shellcheck source=/dev/null
    set -a
    source .env
    set +a
    echo "Loaded environment from .env"
else
    echo -e "${YELLOW}WARN${NC}: .env file not found. Checking environment variables only."
fi

echo ""
echo "==============================================================================="
echo "Checking required secrets"
echo "==============================================================================="

check_secret     "INTERNAL_API_KEY"     "changeme"
check_min_length "INTERNAL_API_KEY"     32

check_secret     "AUTH_SECRET"          "changeme"
check_min_length "AUTH_SECRET"          32

check_secret     "POSTGRES_PASSWORD"    "redamon_secret"
check_secret     "NEO4J_PASSWORD"       "changeme123"
check_secret     "GVM_PASSWORD"         "admin"

echo ""
echo "==============================================================================="
echo "Checking optional / recommended variables"
echo "==============================================================================="

check_not_default "NVD_API_KEY" ""

if [[ "${KB_EMBEDDING_USE_API:-false}" == "true" ]]; then
    check_secret "KB_EMBEDDING_API_KEY" ""
    if [[ -z "${KB_EMBEDDING_API_BASE_URL:-}" ]]; then
        echo -e "${YELLOW}WARN${NC}: KB_EMBEDDING_API_BASE_URL is empty (will default to OpenAI)"
        ((WARNINGS++))
    fi
fi

echo ""
echo "==============================================================================="
if [[ $ERRORS -gt 0 ]]; then
    echo -e "${RED}RESULT: $ERRORS error(s) and $WARNINGS warning(s) found.${NC}"
    echo "Please fix the errors above before running 'docker compose up -d'."
    exit 1
elif [[ $WARNINGS -gt 0 ]]; then
    echo -e "${YELLOW}RESULT: $ERRORS error(s) and $WARNINGS warning(s) found.${NC}"
    echo "The stack will start, but review the warnings for best-practice compliance."
    exit 0
else
    echo -e "${GREEN}RESULT: All checks passed. Environment looks good!${NC}"
    exit 0
fi
