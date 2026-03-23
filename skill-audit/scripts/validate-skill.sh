#!/bin/bash
# Validate skill-audit SKILL.md structure and format
set -euo pipefail

SKILL_FILE="SKILL.md"
ERRORS=0

echo "🔍 Validating skill-audit SKILL.md..."
echo ""

# Check if SKILL.md exists
if [ ! -f "$SKILL_FILE" ]; then
    echo "❌ SKILL.md not found"
    exit 1
fi

# Check frontmatter starts correctly
if ! head -1 "$SKILL_FILE" | grep -q "^---$"; then
    echo "❌ SKILL.md must start with ---"
    ERRORS=$((ERRORS + 1))
else
    echo "✅ Frontmatter starts correctly"
fi

# Check name field
if ! grep -q "^name:" "$SKILL_FILE"; then
    echo "❌ SKILL.md missing name field"
    ERRORS=$((ERRORS + 1))
else
    echo "✅ name field present"
fi

# Check description field
if ! grep -q "^description:" "$SKILL_FILE"; then
    echo "❌ SKILL.md missing description field"
    ERRORS=$((ERRORS + 1))
else
    echo "✅ description field present"
fi

# Check description uses third-person format
if grep "^description:" "$SKILL_FILE" | grep -qv "This skill should be used when"; then
    echo "⚠️  Warning: description should start with 'This skill should be used when'"
fi

# Check for trigger phrases in description
TRIGGER_COUNT=$(grep "^description:" "$SKILL_FILE" | grep -o '"[^"]*"' | wc -l)
if [ "$TRIGGER_COUNT" -lt 4 ]; then
    echo "⚠️  Warning: Consider adding more trigger phrases (found $TRIGGER_COUNT, recommend 4+)"
else
    echo "✅ Trigger phrases present ($TRIGGER_COUNT found)"
fi

# Check license field
if ! grep -q "^license:" "$SKILL_FILE"; then
    echo "⚠️  Warning: Consider adding license field"
else
    echo "✅ license field present"
fi

# Check compatibility field
if ! grep -q "^compatibility:" "$SKILL_FILE"; then
    echo "⚠️  Warning: Consider adding compatibility field"
else
    echo "✅ compatibility field present"
fi

# Check metadata field
if ! grep -q "^metadata:" "$SKILL_FILE"; then
    echo "⚠️  Warning: Consider adding metadata field"
else
    echo "✅ metadata field present"
fi

# Check word count
WORD_COUNT=$(wc -w < "$SKILL_FILE")
echo "📊 Word count: $WORD_COUNT"
if [ "$WORD_COUNT" -gt 2000 ]; then
    echo "⚠️  Warning: SKILL.md has $WORD_COUNT words (recommended: 1,500-2,000)"
    echo "   Consider moving content to references/ directory"
else
    echo "✅ Word count in optimal range"
fi

# Check for progressive disclosure
if [ -d "references" ]; then
    REF_COUNT=$(find references -name "*.md" | wc -l)
    echo "✅ references/ directory exists ($REF_COUNT files)"
else
    echo "⚠️  Warning: No references/ directory found"
fi

if [ -d "examples" ]; then
    EX_COUNT=$(find examples -type f | wc -l)
    echo "✅ examples/ directory exists ($EX_COUNT files)"
else
    echo "⚠️  Warning: No examples/ directory found"
fi

if [ -d "scripts" ]; then
    SCRIPT_COUNT=$(find scripts -name "*.sh" | wc -l)
    echo "✅ scripts/ directory exists ($SCRIPT_COUNT scripts)"
else
    echo "⚠️  Warning: No scripts/ directory found"
fi

# Check for second-person language
if grep -E "\b(you|your|Users can)\b" "$SKILL_FILE" | grep -v "^description" | grep -qv "^#"; then
    echo "⚠️  Warning: Found second-person language (consider using imperative form)"
fi

echo ""
if [ "$ERRORS" -eq 0 ]; then
    echo "✅ SKILL.md validation passed"
    exit 0
else
    echo "❌ SKILL.md validation failed with $ERRORS error(s)"
    exit 1
fi