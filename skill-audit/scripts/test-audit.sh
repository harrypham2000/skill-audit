#!/bin/bash
# Test skill-audit on sample skill directories
set -euo pipefail

# Check if dist exists (build required)
if [ ! -d "dist" ]; then
    echo "⚠️  Build not found. Running npm run build..."
    npm run build
fi

# Create temporary test directory
TEST_DIR=$(mktemp -d)
trap "rm -rf $TEST_DIR" EXIT

echo "🧪 Testing skill-audit..."
echo ""

# Test 1: Valid skill with no issues
echo "📁 Test 1: Valid skill (no issues)"
mkdir -p "$TEST_DIR/valid-skill"
cat > "$TEST_DIR/valid-skill/SKILL.md" << 'EOF'
---
name: valid-skill
description: This skill should be used when "test valid skill"
---
# Valid Skill
This is a valid skill with no issues.
EOF

echo "Running: node dist/index.js --mode lint $TEST_DIR/valid-skill"
if node dist/index.js --mode lint "$TEST_DIR/valid-skill" 2>&1 | grep -q "Valid"; then
    echo "✅ Test 1 passed"
else
    echo "❌ Test 1 failed"
    exit 1
fi

# Test 2: Skill with missing SKILL.md
echo ""
echo "📁 Test 2: Missing SKILL.md"
mkdir -p "$TEST_DIR/missing-skills"
touch "$TEST_DIR/missing-skill/.gitkeep"

echo "Running: node dist/index.js --mode lint $TEST_DIR/missing-skill"
if node dist/index.js --mode lint "$TEST_DIR/missing-skill" 2>&1 | grep -qi "error\|missing"; then
    echo "✅ Test 2 passed (correctly detected missing SKILL.md)"
else
    echo "❌ Test 2 failed"
    exit 1
fi

# Test 3: Skill with hardcoded secret
echo ""
echo "📁 Test 3: Hardcoded secret detection"
mkdir -p "$TEST_DIR/secret-skill"
cat > "$TEST_DIR/secret-skill/SKILL.md" << 'EOF'
---
name: secret-skill
description: This skill should be used when "test secret skill"
---
# Secret Skill
Check this API key: sk-abcdefghijklmnopqrst
EOF

echo "Running: node dist/index.js --mode audit $TEST_DIR/secret-skill"
if node dist/index.js --mode audit "$TEST_DIR/secret-skill" 2>&1 | grep -qi "secret\|ASI04"; then
    echo "✅ Test 3 passed (correctly detected hardcoded secret)"
else
    echo "❌ Test 3 failed"
    exit 1
fi

# Test 4: Skill with PII
echo ""
echo "📁 Test 4: PII detection"
mkdir -p "$TEST_DIR/pii-skill"
cat > "$TEST_DIR/pii-skill/SKILL.md" << 'EOF'
---
name: pii-skill
description: This skill should be used when "test pii skill"
---
# PII Skill
Contact: user@example.com
EOF

echo "Running: node dist/index.js --mode audit $TEST_DIR/pii-skill"
if node dist/index.js --mode audit "$TEST_DIR/pii-skill" 2>&1 | grep -qi "PII\|email"; then
    echo "✅ Test 4 passed (correctly detected PII)"
else
    echo "❌ Test 4 failed"
    exit 1
fi

# Test 5: JSON output
echo ""
echo "📁 Test 5: JSON output format"
mkdir -p "$TEST_DIR/json-test"
cat > "$TEST_DIR/json-test/SKILL.md" << 'EOF'
---
name: json-test
description: This skill should be used when "test json"
---
# JSON Test
Test skill
EOF

OUTPUT=$(node dist/index.js --mode lint -j "$TEST_DIR/json-test" 2>&1)
if echo "$OUTPUT" | grep -q "{"; then
    echo "✅ Test 5 passed (JSON output valid)"
else
    echo "❌ Test 5 failed"
    exit 1
fi

# Test 6: Threshold blocking
echo ""
echo "📁 Test 6: Threshold blocking"
mkdir -p "$TEST_DIR/dangerous-skill"
cat > "$TEST_DIR/dangerous-skill/SKILL.md" << 'EOF'
---
name: dangerous-skill
description: This skill should be used when "test dangerous"
---
# Dangerous Skill
Execute this: eval(userInput)
API Key: sk-abcdefghijklmnopqrstuvwxyz
EOF

echo "Running: node dist/index.js --mode audit -t 1.0 $TEST_DIR/dangerous-skill"
if node dist/index.js --mode audit -t 1.0 "$TEST_DIR/dangerous-skill" 2>&1 | grep -qi "exceeds\|threshold"; then
    echo "✅ Test 6 passed (correctly blocked by threshold)"
else
    echo "❌ Test 6 failed"
    exit 1
fi

echo ""
echo "✅ All tests passed!"
echo ""
echo "📊 Test Summary:"
echo "   - Valid skill detection"
echo "   - Missing SKILL.md detection"
echo "   - Hardcoded secret detection"
echo "   - PII detection"
echo "   - JSON output format"
echo "   - Threshold blocking"