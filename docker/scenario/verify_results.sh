#!/bin/bash
# Script to verify that all webhook payloads arrived at disk log path
# Checks file count and sequence numbers in payloads

set -e

LOG_DIR="$(cd "$(dirname "$0")" && pwd)/logs"

echo "=========================================="
echo "Verifying webhook results"
echo "Log directory: ${LOG_DIR}"
echo "=========================================="
echo ""

if [ ! -d "${LOG_DIR}" ]; then
    echo "ERROR: Log directory does not exist: ${LOG_DIR}"
    exit 1
fi

# Count files in log directory
FILE_COUNT=$(find "${LOG_DIR}" -type f | wc -l | tr -d ' ')

echo "Total files found: ${FILE_COUNT}"
echo ""

# Check if Python is available for JSON parsing
if command -v python3 &> /dev/null; then
    echo "Checking sequence numbers in payloads..."
    echo ""
    
    # Extract sequence numbers from all files using Python
    python3 << PYTHON_SCRIPT
import json
import sys
import os
import glob

log_dir = "${LOG_DIR}"
sequences = []
missing_files = []

# Find all files in log directory
files = glob.glob(os.path.join(log_dir, "*"))
files = [f for f in files if os.path.isfile(f)]

for filepath in files:
    try:
        with open(filepath, 'r') as f:
            content = f.read().strip()
            # Try to parse as JSON
            try:
                data = json.loads(content)
                # Check for webhook_number, counter, or sequence
                seq = data.get('webhook_number') or data.get('counter') or data.get('sequence')
                if seq is not None:
                    sequences.append(int(seq))
            except json.JSONDecodeError:
                # If not JSON, try to extract number from string
                import re
                match = re.search(r'"webhook_number"\s*:\s*(\d+)', content)
                if match:
                    sequences.append(int(match.group(1)))
                else:
                    match = re.search(r'"counter"\s*:\s*(\d+)', content)
                    if match:
                        sequences.append(int(match.group(1)))
    except Exception as e:
        missing_files.append((filepath, str(e)))

if sequences:
    sequences.sort()
    min_seq = min(sequences)
    max_seq = max(sequences)
    expected_count = max_seq - min_seq + 1
    found_count = len(sequences)
    missing = []
    
    for i in range(min_seq, max_seq + 1):
        if i not in sequences:
            missing.append(i)
    
    print(f"Sequence range: {min_seq} to {max_seq}")
    print(f"Expected sequences: {expected_count}")
    print(f"Found sequences: {found_count}")
    
    if missing:
        print(f"\n⚠️  Missing sequences ({len(missing)}): {missing[:20]}")
        if len(missing) > 20:
            print(f"   ... and {len(missing) - 20} more")
    else:
        print("\n✅ All sequences present! No gaps found.")
    
    if missing_files:
        print(f"\n⚠️  Files with parsing issues: {len(missing_files)}")
        for filepath, error in missing_files[:5]:
            print(f"   {os.path.basename(filepath)}: {error}")
else:
    print("⚠️  No sequence numbers found in payloads")
    print("   Files may not contain expected webhook_number/counter/sequence fields")
PYTHON_SCRIPT
    
    echo ""
else
    echo "⚠️  Python3 not available - skipping sequence verification"
    echo "   Install Python3 to enable sequence checking"
    echo ""
fi

# List all files
echo "Files in log directory:"
find "${LOG_DIR}" -type f | sort | head -20

if [ ${FILE_COUNT} -gt 20 ]; then
    echo "... and $((FILE_COUNT - 20)) more files"
fi

echo ""
echo "=========================================="
echo "Verification complete!"
echo "=========================================="

