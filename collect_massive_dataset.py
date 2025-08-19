#!/usr/bin/env python3
"""
Massive Dataset Collector - Automatically runs multiple queries to collect 100k+ vulnerability data
"""

import os
import subprocess
import time
import csv
import json
from pathlib import Path
from datetime import datetime, timedelta
import argparse

# Define comprehensive search strategies
SEARCH_STRATEGIES = {
    "cve_years": [
        "CVE-2024 fix -org:CVEProject",
        "CVE-2023 fix -org:CVEProject", 
        "CVE-2022 fix -org:CVEProject",
        "CVE-2021 fix -org:CVEProject",
        "CVE-2020 fix -org:CVEProject",
    ],
    
    "vulnerability_keywords": [
        "security vulnerability fix",
        "buffer overflow fix",
        "sql injection fix", 
        "xss fix cross-site scripting",
        "path traversal fix",
        "command injection fix",
        "authentication bypass fix",
        "privilege escalation fix",
        "memory corruption fix",
        "integer overflow fix",
        "null pointer dereference fix",
        "use after free fix",
        "heap overflow fix",
        "stack overflow fix",
        "format string fix",
    ],
    
    "language_specific": [
        "CVE fix language:python",
        "CVE fix language:java", 
        "CVE fix language:javascript",
        "CVE fix language:c",
        "CVE fix language:cpp",
        "CVE fix language:go",
        "CVE fix language:rust",
        "CVE fix language:php",
        "security fix language:python",
        "vulnerability fix language:java",
        "buffer overflow language:c",
        "sql injection language:python",
        "xss fix language:javascript",
    ],
    
    "cwe_specific": [
        "CWE-79 fix",
        "CWE-89 fix", 
        "CWE-22 fix",
        "CWE-78 fix",
        "CWE-119 fix",
        "CWE-125 fix",
        "CWE-787 fix",
        "CWE-476 fix",
        "CWE-190 fix",
        "CWE-352 fix",
        "CWE-20 fix",
        "CWE-200 fix",
    ],
    
    "date_ranges_2024": [
        "CVE fix created:2024-01-01..2024-02-29",
        "CVE fix created:2024-03-01..2024-04-30", 
        "CVE fix created:2024-05-01..2024-06-30",
        "CVE fix created:2024-07-01..2024-08-31",
        "CVE fix created:2024-09-01..2024-10-31",
        "CVE fix created:2024-11-01..2024-12-31",
    ],
    
    "security_terms": [
        "security patch",
        "vulnerability patch",
        "exploit fix",
        "security issue fix", 
        "DoS fix denial of service",
        "RCE fix remote code execution",
        "LFI fix local file inclusion",
        "RFI fix remote file inclusion",
        "CSRF fix",
        "XXE fix",
        "LDAP injection fix",
        "XML injection fix",
    ]
}

def run_crawler(query: str, output_file: str, max_results: int = 1000) -> dict:
    """Run the optimized crawler for a single query"""
    cmd = [
        "python3", "github_cwe_crawler_optimized.py",
        "--query", query,
        "--max-results", str(max_results),
        "--output", output_file,
        "--threads", "4"
    ]
    
    print(f"Running: {query} -> {output_file}")
    
    try:
        start_time = time.time()
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=1800)  # 30min timeout
        duration = time.time() - start_time
        
        if result.returncode == 0:
            # Parse stats from output
            output_lines = result.stdout.split('\n')
            stats = {"success": True, "duration": duration, "query": query, "output_file": output_file}
            
            for line in output_lines:
                if "Wrote" in line and "rows" in line:
                    try:
                        rows = int(line.split()[1])
                        stats["rows"] = rows
                    except:
                        stats["rows"] = 0
                elif "Unique commits processed:" in line:
                    try:
                        commits = int(line.split()[-1])
                        stats["unique_commits"] = commits
                    except:
                        pass
                elif "Python-specific results:" in line:
                    try:
                        python_files = int(line.split()[2])
                        stats["python_files"] = python_files
                    except:
                        pass
            
            return stats
        else:
            print(f"ERROR: {query}")
            print(f"STDERR: {result.stderr}")
            return {"success": False, "query": query, "error": result.stderr}
            
    except subprocess.TimeoutExpired:
        print(f"TIMEOUT: {query}")
        return {"success": False, "query": query, "error": "timeout"}
    except Exception as e:
        print(f"EXCEPTION: {query} - {e}")
        return {"success": False, "query": query, "error": str(e)}

def combine_csv_files(output_files: list, final_output: str):
    """Combine multiple CSV files into one, removing duplicates"""
    print(f"\nCombining {len(output_files)} CSV files into {final_output}")
    
    seen_commits = set()
    seen_code_hashes = set()
    total_rows = 0
    unique_rows = 0
    
    fieldnames = ["dataset", "func_name", "code", "prompts", "vulnerable_code", "non_vulnerable_code", "vul_type", "commit_link", "file_name"]
    
    with open(final_output, 'w', encoding='utf-8', newline='') as outfile:
        writer = csv.DictWriter(outfile, fieldnames=fieldnames, quoting=csv.QUOTE_ALL)
        writer.writeheader()
        
        for csv_file in output_files:
            if not Path(csv_file).exists():
                continue
                
            try:
                with open(csv_file, 'r', encoding='utf-8') as infile:
                    reader = csv.DictReader(infile)
                    for row in reader:
                        total_rows += 1
                        
                        # Check for duplicates
                        commit_link = row.get('commit_link', '')
                        code = row.get('code', '')
                        code_hash = hash(code)
                        
                        if commit_link not in seen_commits and code_hash not in seen_code_hashes:
                            seen_commits.add(commit_link)
                            seen_code_hashes.add(code_hash)
                            writer.writerow(row)
                            unique_rows += 1
                            
            except Exception as e:
                print(f"Error reading {csv_file}: {e}")
    
    print(f"Combined results:")
    print(f"  Total rows processed: {total_rows}")
    print(f"  Unique rows written: {unique_rows}")
    print(f"  Duplicates removed: {total_rows - unique_rows}")
    
    return unique_rows

def main():
    parser = argparse.ArgumentParser(description="Collect massive vulnerability dataset")
    parser.add_argument("--target-size", type=int, default=100000, help="Target number of data points")
    parser.add_argument("--output-dir", default="./datasets", help="Output directory")
    parser.add_argument("--final-output", default="massive_vulnerability_dataset.csv", help="Final combined CSV")
    parser.add_argument("--strategies", nargs="+", 
                       choices=list(SEARCH_STRATEGIES.keys()) + ["all"],
                       default=["all"], help="Which search strategies to use")
    args = parser.parse_args()
    
    # Create output directory
    output_dir = Path(args.output_dir)
    output_dir.mkdir(exist_ok=True)
    
    # Determine which strategies to use
    if "all" in args.strategies:
        strategies_to_use = list(SEARCH_STRATEGIES.keys())
    else:
        strategies_to_use = args.strategies
    
    # Collect all queries
    all_queries = []
    for strategy in strategies_to_use:
        all_queries.extend(SEARCH_STRATEGIES[strategy])
    
    print(f"Will run {len(all_queries)} queries to collect ~{args.target_size} data points")
    print(f"Estimated time: {len(all_queries) * 3} minutes")
    
    # Run queries
    results = []
    output_files = []
    total_rows = 0
    
    for i, query in enumerate(all_queries):
        if total_rows >= args.target_size:
            print(f"Reached target size of {args.target_size}, stopping early")
            break
            
        output_file = output_dir / f"batch_{i:03d}.csv"
        output_files.append(str(output_file))
        
        stats = run_crawler(query, str(output_file))
        results.append(stats)
        
        if stats.get("success") and stats.get("rows", 0) > 0:
            total_rows += stats["rows"]
            print(f"Progress: {total_rows}/{args.target_size} rows collected")
        
        # Small delay to be nice to GitHub API
        time.sleep(2)
    
    # Save execution log
    log_file = output_dir / "execution_log.json"
    with open(log_file, 'w') as f:
        json.dump({
            "timestamp": datetime.now().isoformat(),
            "target_size": args.target_size,
            "total_queries": len(all_queries),
            "successful_queries": sum(1 for r in results if r.get("success")),
            "total_rows_collected": total_rows,
            "results": results
        }, f, indent=2)
    
    # Combine all CSV files
    final_rows = combine_csv_files(output_files, args.final_output)
    
    # Cleanup individual files if requested
    print(f"\nKeeping individual CSV files in {output_dir}")
    print(f"Final combined dataset: {args.final_output} ({final_rows} unique rows)")
    
    # Run duplicate check on final file
    print("\nRunning final duplicate check...")
    subprocess.run(["python3", "check_duplicates.py", args.final_output])

if __name__ == "__main__":
    main()