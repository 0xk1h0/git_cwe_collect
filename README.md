# Felina

---

Just run this single command:
  ./collect_100k.sh

  📋 What it does automatically:

  1. 75+ different search queries across:
    - CVE years (2020-2024)
    - Vulnerability types (XSS, SQLi, buffer overflow, etc.)
    - Languages (Python, Java, C, JavaScript, etc.)
    - CWE-specific searches
    - Date ranges
    - Security terms
  2. Smart duplicate removal at multiple levels:
    - Commit-level deduplication
    - Code-content deduplication
    - Cross-file deduplication
  3. Progress tracking:
    - Shows real-time progress toward 100k target
    - Stops automatically when target reached
    - Saves execution logs
  4. Automatic combination:
    - Merges all CSV files into one final dataset
    - Removes duplicates across all files
    - Provides final statistics

  📊 Expected Results:

  - 100,000+ unique vulnerability code samples
  - High CWE coverage (20+ different vulnerability types)
  - Multi-language support (Python, Java, C, JavaScript, etc.)
  - 4-6 hours runtime (runs completely unattended)

  🔧 Manual control available:

  ### Collect specific strategies only
  python3 collect_massive_dataset.py --strategies cve_years
  language_specific --target-size 50000

  ### Custom target size
  python3 collect_massive_dataset.py --target-size 200000