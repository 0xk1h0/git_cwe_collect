#!/bin/bash
# Automated 100k+ vulnerability dataset collection

echo "🚀 Starting massive vulnerability dataset collection..."
echo "📊 Target: 100,000+ unique vulnerability code samples"
echo "⏱️  Estimated time: 4-6 hours"
echo ""

# Check if required files exist
if [ ! -f "github_cwe_crawler_optimized.py" ]; then
    echo "❌ Error: github_cwe_crawler_optimized.py not found"
    exit 1
fi

if [ ! -f "check_duplicates.py" ]; then
    echo "❌ Error: check_duplicates.py not found"
    exit 1
fi

# Check for GitHub token
if [ -z "$GITHUB_TOKEN" ]; then
    echo "⚠️  WARNING: GITHUB_TOKEN not set. You may hit rate limits faster."
    echo "   Set it with: export GITHUB_TOKEN=your_token_here"
    echo ""
fi

# Create timestamp for this run
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
OUTPUT_DIR="datasets_$TIMESTAMP"
FINAL_OUTPUT="vulnerability_dataset_${TIMESTAMP}.csv"

echo "📁 Output directory: $OUTPUT_DIR"
echo "📄 Final dataset: $FINAL_OUTPUT"
echo ""

# Run the massive collection
python3 collect_massive_dataset.py \
    --target-size 100000 \
    --output-dir "$OUTPUT_DIR" \
    --final-output "$FINAL_OUTPUT" \
    --strategies all

# Check if successful
if [ $? -eq 0 ]; then
    echo ""
    echo "✅ Collection completed successfully!"
    echo "📊 Final dataset: $FINAL_OUTPUT"
    echo "📁 Individual files: $OUTPUT_DIR/"
    echo ""
    
    # Show final stats
    if [ -f "$FINAL_OUTPUT" ]; then
        TOTAL_LINES=$(wc -l < "$FINAL_OUTPUT")
        echo "📈 Final dataset contains: $((TOTAL_LINES - 1)) rows"
        
        # Show first few lines
        echo ""
        echo "🔍 Dataset preview:"
        head -3 "$FINAL_OUTPUT"
        echo "..."
    fi
    
else
    echo ""
    echo "❌ Collection failed. Check the logs above."
    exit 1
fi