#!/usr/bin/env python3
"""
Check for duplicates across multiple CSV files
"""

import csv
import sys
import hashlib
from pathlib import Path

def hash_code(code_text):
    """Create hash of code content for duplicate detection"""
    # Normalize whitespace and remove comments for better duplicate detection
    normalized = ' '.join(code_text.split())
    return hashlib.md5(normalized.encode()).hexdigest()

def analyze_csv_file(csv_path):
    """Analyze a single CSV file for duplicates and statistics"""
    print(f"\nAnalyzing {csv_path}:")
    
    rows = []
    seen_hashes = set()
    seen_commits = set()
    duplicates = 0
    
    try:
        with open(csv_path, 'r', encoding='utf-8') as f:
            reader = csv.DictReader(f)
            for row in reader:
                rows.append(row)
                
                # Check commit duplicates
                commit_link = row.get('commit_link', '')
                if commit_link in seen_commits:
                    duplicates += 1
                else:
                    seen_commits.add(commit_link)
                
                # Check code duplicates
                code = row.get('code', '')
                code_hash = hash_code(code)
                seen_hashes.add(code_hash)
        
        total_rows = len(rows)
        unique_code = len(seen_hashes)
        unique_commits = len(seen_commits)
        
        print(f"  Total rows: {total_rows}")
        print(f"  Unique commits: {unique_commits}")
        print(f"  Unique code snippets: {unique_code}")
        print(f"  Duplicate commits: {total_rows - unique_commits}")
        
        # CWE distribution
        cwe_counts = {}
        lang_counts = {}
        python_count = 0
        
        for row in rows:
            cwe = row.get('vul_type', 'unknown')
            cwe_counts[cwe] = cwe_counts.get(cwe, 0) + 1
            
            filename = row.get('file_name', '')
            if filename.endswith('.py'):
                python_count += 1
            
            if '.' in filename:
                ext = filename.split('.')[-1]
                lang_counts[ext] = lang_counts.get(ext, 0) + 1
        
        print(f"  Python files: {python_count}")
        print(f"  Top CWEs: {dict(sorted(cwe_counts.items(), key=lambda x: x[1], reverse=True)[:5])}")
        print(f"  Top languages: {dict(sorted(lang_counts.items(), key=lambda x: x[1], reverse=True)[:5])}")
        
        return {
            'total_rows': total_rows,
            'unique_commits': unique_commits,
            'unique_code': unique_code,
            'python_count': python_count,
            'cwe_counts': cwe_counts,
            'lang_counts': lang_counts,
            'rows': rows
        }
        
    except Exception as e:
        print(f"  Error reading file: {e}")
        return None

def compare_multiple_files(csv_files):
    """Compare multiple CSV files for cross-file duplicates"""
    print(f"\nComparing {len(csv_files)} files for cross-file duplicates...")
    
    all_commits = set()
    all_code_hashes = set()
    total_rows = 0
    cross_file_commit_dups = 0
    cross_file_code_dups = 0
    
    for csv_path in csv_files:
        try:
            with open(csv_path, 'r', encoding='utf-8') as f:
                reader = csv.DictReader(f)
                for row in reader:
                    total_rows += 1
                    
                    # Check commit duplicates across files
                    commit_link = row.get('commit_link', '')
                    if commit_link in all_commits:
                        cross_file_commit_dups += 1
                    else:
                        all_commits.add(commit_link)
                    
                    # Check code duplicates across files
                    code = row.get('code', '')
                    code_hash = hash_code(code)
                    if code_hash in all_code_hashes:
                        cross_file_code_dups += 1
                    else:
                        all_code_hashes.add(code_hash)
        except Exception as e:
            print(f"Error reading {csv_path}: {e}")
    
    print(f"Cross-file analysis:")
    print(f"  Total rows across all files: {total_rows}")
    print(f"  Unique commits across all files: {len(all_commits)}")
    print(f"  Unique code snippets across all files: {len(all_code_hashes)}")
    print(f"  Cross-file duplicate commits: {cross_file_commit_dups}")
    print(f"  Cross-file duplicate code: {cross_file_code_dups}")

def main():
    if len(sys.argv) < 2:
        print("Usage: python3 check_duplicates.py file1.csv [file2.csv ...]")
        sys.exit(1)
    
    csv_files = sys.argv[1:]
    
    # Check each file individually
    file_stats = []
    for csv_file in csv_files:
        if Path(csv_file).exists():
            stats = analyze_csv_file(csv_file)
            if stats:
                file_stats.append(stats)
        else:
            print(f"File not found: {csv_file}")
    
    # Compare across files if multiple files
    if len(csv_files) > 1:
        compare_multiple_files(csv_files)
    
    # Summary
    if file_stats:
        total_python = sum(s['python_count'] for s in file_stats)
        total_unique_commits = sum(s['unique_commits'] for s in file_stats)
        total_unique_code = sum(s['unique_code'] for s in file_stats)
        
        print(f"\nOverall Summary:")
        print(f"  Total Python files: {total_python}")
        print(f"  Total unique commits: {total_unique_commits}")
        print(f"  Total unique code snippets: {total_unique_code}")

if __name__ == "__main__":
    main()