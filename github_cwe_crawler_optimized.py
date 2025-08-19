#!/usr/bin/env python3
"""
Optimized GitHub CWE Crawler - Fast vulnerability dataset collection
"""

import os
import re
import csv
import sys
import time
import json
import base64
import argparse
from typing import Dict, List, Optional, Tuple, Set
import requests
from tqdm import tqdm
from concurrent.futures import ThreadPoolExecutor, as_completed
import threading

GITHUB_API = "https://api.github.com"
NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"

GITHUB_TOKEN = os.getenv("GITHUB_TOKEN", "")
HEADERS = {
    "Accept": "application/vnd.github+json",
    "User-Agent": "cwe-fix-crawler/0.3-optimized",
}
if GITHUB_TOKEN:
    HEADERS["Authorization"] = f"Bearer {GITHUB_TOKEN}"

# Skip meta repos
SKIP_REPOS = {
    "CVEProject/cvelistV5", "CVEProject/cvelist", "github/advisory-database"
}

# Source file extensions
ALLOWED_EXTS = {
    ".c", ".cc", ".cpp", ".h", ".hpp", ".java", ".kt", ".py", 
    ".js", ".jsx", ".ts", ".tsx", ".go", ".rb", ".php", ".rs", ".cs", ".swift"
}

# Global cache and rate limiting
_rate_limit_lock = threading.Lock()
_last_api_call = 0
_cve_cwe_cache = {}

def rate_limited_request(session: requests.Session, url: str, **kwargs) -> requests.Response:
    """Rate-limited request with exponential backoff"""
    global _last_api_call
    
    with _rate_limit_lock:
        # Ensure at least 0.5s between requests
        elapsed = time.time() - _last_api_call
        if elapsed < 0.5:
            time.sleep(0.5 - elapsed)
        _last_api_call = time.time()
    
    for attempt in range(4):
        try:
            r = session.get(url, timeout=30, **kwargs)
            if r.status_code == 403:
                wait_time = min(60 * (2 ** attempt), 300)  # Exponential backoff, max 5min
                print(f"Rate limited, waiting {wait_time}s (attempt {attempt+1})", file=sys.stderr)
                time.sleep(wait_time)
                continue
            elif r.status_code == 422:
                print(f"API error 422: {r.text[:200]}", file=sys.stderr)
                return r
            r.raise_for_status()
            return r
        except requests.RequestException as e:
            if attempt == 3:
                raise
            time.sleep(2 ** attempt)
    
    raise Exception(f"Failed after 4 attempts: {url}")

def search_commits_fast(query: str, max_results: int) -> List[Dict]:
    """Fast commit search with minimal API calls"""
    session = requests.Session()
    session.headers.update(HEADERS)
    
    url = f"{GITHUB_API}/search/commits"
    params = {"q": query, "sort": "committer-date", "order": "desc", "per_page": 100}
    
    items = []
    while len(items) < max_results:
        r = rate_limited_request(session, url, params=params)
        data = r.json()
        batch = data.get("items", [])
        items.extend(batch)
        
        # Check for next page
        link = r.headers.get("Link", "")
        next_url = None
        for part in link.split(","):
            if 'rel="next"' in part:
                next_url = part[part.find("<")+1:part.find(">")]
                break
        
        if not next_url or len(batch) < 100:
            break
            
        url = next_url
        params = {}
    
    return items[:max_results]

def extract_cwe_patterns(text: str) -> Optional[str]:
    """Enhanced CWE extraction with multiple patterns"""
    if not text:
        return None
    
    text_lower = text.lower()
    
    # Direct CWE mentions
    cwe_match = re.search(r"cwe-(\d+)", text_lower)
    if cwe_match:
        return f"cwe-{cwe_match.group(1)}"
    
    # Common vulnerability patterns mapping
    patterns = {
        "cwe-79": ["xss", "cross-site scripting", "script injection", "html injection", "dom manipulation"],
        "cwe-89": ["sql injection", "sqli", "database injection", "sql query", "prepared statement"],
        "cwe-78": ["command injection", "os injection", "shell injection", "exec", "system call"],
        "cwe-22": ["path traversal", "directory traversal", "../", "path manipulation", "file access"],
        "cwe-352": ["csrf", "cross-site request forgery", "token validation", "csrf token"],
        "cwe-20": ["input validation", "sanitize", "validate input", "user input", "untrusted"],
        "cwe-119": ["buffer overflow", "stack overflow", "heap overflow", "memory corruption"],
        "cwe-125": ["buffer overread", "out-of-bounds read", "read overflow"],
        "cwe-787": ["buffer overwrite", "out-of-bounds write", "write overflow"],
        "cwe-190": ["integer overflow", "arithmetic overflow", "numeric overflow"],
        "cwe-476": ["null pointer", "null dereference", "nullptr", "segfault"],
        "cwe-416": ["use after free", "dangling pointer", "freed memory"],
        "cwe-401": ["memory leak", "resource leak", "heap leak"],
        "cwe-200": ["information disclosure", "sensitive data", "data leak", "exposure"],
        "cwe-94": ["code injection", "eval", "dynamic code", "script execution"],
        "cwe-434": ["file upload", "unrestricted upload", "malicious file"],
        "cwe-862": ["authentication", "auth bypass", "unauthorized access"],
        "cwe-863": ["authorization", "privilege escalation", "access control"],
    }
    
    for cwe, keywords in patterns.items():
        if any(keyword in text_lower for keyword in keywords):
            return cwe
    
    return None

def get_cwe_from_cve(cve_id: str, session: requests.Session) -> Optional[str]:
    """Get CWE from CVE with caching"""
    global _cve_cwe_cache
    
    if cve_id in _cve_cwe_cache:
        return _cve_cwe_cache[cve_id]
    
    try:
        r = rate_limited_request(session, NVD_API, params={"cveId": cve_id})
        data = r.json()
        
        vulnerabilities = data.get("vulnerabilities", [])
        if vulnerabilities:
            weaknesses = vulnerabilities[0].get("cve", {}).get("weaknesses", [])
            if weaknesses:
                descriptions = weaknesses[0].get("description", [])
                if descriptions:
                    value = descriptions[0].get("value", "")
                    cwe_match = re.search(r"CWE-\d+", value)
                    if cwe_match:
                        result = cwe_match.group(0).lower()
                        _cve_cwe_cache[cve_id] = result
                        return result
    except Exception:
        pass
    
    _cve_cwe_cache[cve_id] = None
    return None

def extract_code_snippet(code: str, around_line: int, max_lines: int = 30) -> str:
    """Extract focused code snippet around a line"""
    if not code:
        return ""
    
    lines = code.splitlines()
    start = max(0, around_line - 15)
    end = min(len(lines), around_line + 15, start + max_lines)
    
    return "\n".join(lines[start:end])

def process_commit_fast(commit_item: Dict, session: requests.Session, seen_commits: set) -> List[Dict]:
    """Fast commit processing with minimal API calls and duplicate detection"""
    commit_url = commit_item["url"]
    html_url = commit_item.get("html_url", "")
    
    # Extract commit SHA for duplicate detection
    sha = commit_item.get("sha") or commit_url.split("/")[-1]
    if sha in seen_commits:
        return []  # Skip duplicate
    seen_commits.add(sha)
    
    # Extract repo info
    repo_match = re.search(r"/repos/([^/]+/[^/]+)/commits/", commit_url)
    if not repo_match:
        return []
    
    repo_fullname = repo_match.group(1)
    if repo_fullname in SKIP_REPOS:
        return []
    
    try:
        # Get commit details
        r = rate_limited_request(session, commit_url)
        commit = r.json()
        
        files = commit.get("files", [])
        if not files:
            return []
        
        # Extract vulnerability info
        commit_msg = commit.get("commit", {}).get("message", "")
        cve_ids = re.findall(r"CVE-\d{4}-\d{4,7}", commit_msg, re.I)
        
        # Get CWE - prioritize pattern matching over API calls
        cwe_id = extract_cwe_patterns(commit_msg)
        if not cwe_id and cve_ids:
            cwe_id = get_cwe_from_cve(cve_ids[0], session)  # Only check first CVE
        
        if not cwe_id:
            cwe_id = "unknown"
        
        results = []
        for f in files[:3]:  # Limit to first 3 files per commit
            filename = f.get("filename", "")
            if not any(filename.endswith(ext) for ext in ALLOWED_EXTS):
                continue
            
            patch = f.get("patch", "")
            if not patch or f.get("status") not in {"modified", "changed"}:
                continue
            
            # Simple hunk parsing
            lines = patch.split("\n")
            add_line = None
            for line in lines:
                if line.startswith("@@"):
                    match = re.search(r"@@ -\d+(?:,\d+)? \+(\d+)", line)
                    if match:
                        add_line = int(match.group(1))
                        break
            
            if not add_line:
                continue
            
            # Extract code snippets (simplified - use patch content)
            patch_lines = [l[1:] for l in lines if l.startswith(('+', '-', ' '))]
            code_snippet = "\n".join(patch_lines[:30])  # Limit size
            
            # Create basic prompts based on language
            lang = "unknown"
            for ext in ALLOWED_EXTS:
                if filename.endswith(ext):
                    lang = ext[1:]  # Remove dot
                    break
            
            prompt = f"Write a secure {lang} function that fixes the vulnerability shown in {filename}"
            if cwe_id != "unknown":
                prompt += f" (avoiding {cwe_id.upper()})"
            
            row = {
                "dataset": "train_sec",
                "func_name": "unknown",
                "code": code_snippet,
                "prompts": prompt,
                "vulnerable_code": code_snippet,
                "non_vulnerable_code": code_snippet,
                "vul_type": cwe_id,
                "commit_link": html_url or commit_url,
                "file_name": filename,
            }
            results.append(row)
        
        return results
        
    except Exception as e:
        print(f"Error processing {commit_url}: {e}", file=sys.stderr)
        return []

def main():
    parser = argparse.ArgumentParser(description="Fast GitHub vulnerability dataset crawler")
    parser.add_argument("--query", required=True, help="GitHub search query")
    parser.add_argument("--max-results", type=int, default=100, help="Max commits to process")
    parser.add_argument("--output", default="fast_dataset.csv", help="Output CSV file")
    parser.add_argument("--threads", type=int, default=4, help="Number of threads")
    args = parser.parse_args()
    
    if not GITHUB_TOKEN:
        print("WARNING: Set GITHUB_TOKEN for higher rate limits", file=sys.stderr)
    
    print(f"Searching for commits: {args.query}")
    commits = search_commits_fast(args.query, args.max_results)
    print(f"Found {len(commits)} commits")
    
    # Process commits with threading and duplicate detection
    all_rows = []
    seen_commits = set()
    seen_code_hashes = set()
    session = requests.Session()
    session.headers.update(HEADERS)
    
    with ThreadPoolExecutor(max_workers=min(args.threads, 2)) as executor:  # Conservative threading
        futures = {executor.submit(process_commit_fast, commit, session, seen_commits): commit for commit in commits}
        
        for future in tqdm(as_completed(futures), total=len(futures), desc="Processing"):
            try:
                rows = future.result()
                # Additional deduplication by code content
                for row in rows:
                    code_hash = hash(row["code"])
                    if code_hash not in seen_code_hashes:
                        seen_code_hashes.add(code_hash)
                        all_rows.append(row)
            except Exception as e:
                print(f"Thread error: {e}", file=sys.stderr)
    
    # Write results
    fieldnames = ["dataset", "func_name", "code", "prompts", "vulnerable_code", "non_vulnerable_code", "vul_type", "commit_link", "file_name"]
    
    with open(args.output, "w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames, quoting=csv.QUOTE_ALL)
        writer.writeheader()
        for row in all_rows:
            # Clean text for CSV
            for field in ["code", "vulnerable_code", "non_vulnerable_code", "prompts"]:
                if row.get(field):
                    row[field] = row[field].replace('"', '""').replace('\n', ' ')[:500]  # Limit length
            writer.writerow(row)
    
    print(f"Wrote {len(all_rows)} rows to {args.output}")
    
    # Show statistics
    total_commits = len(commits)
    duplicate_commits = total_commits - len(seen_commits)
    duplicate_code = len(seen_code_hashes) - len(all_rows) if len(seen_code_hashes) > len(all_rows) else 0
    
    print(f"\nStatistics:")
    print(f"  Total commits found: {total_commits}")
    print(f"  Unique commits processed: {len(seen_commits)}")
    print(f"  Duplicate commits skipped: {duplicate_commits}")
    print(f"  Unique code snippets: {len(all_rows)}")
    print(f"  Duplicate code snippets skipped: {duplicate_code}")
    
    # Show CWE distribution
    cwe_counts = {}
    lang_counts = {}
    for row in all_rows:
        cwe = row["vul_type"]
        cwe_counts[cwe] = cwe_counts.get(cwe, 0) + 1
        
        # Count by file extension
        filename = row["file_name"]
        ext = filename.split(".")[-1] if "." in filename else "unknown"
        lang_counts[ext] = lang_counts.get(ext, 0) + 1
    
    print(f"\nCWE Distribution:")
    for cwe, count in sorted(cwe_counts.items(), key=lambda x: x[1], reverse=True)[:10]:
        print(f"  {cwe}: {count}")
    
    print(f"\nLanguage Distribution:")
    for lang, count in sorted(lang_counts.items(), key=lambda x: x[1], reverse=True)[:10]:
        print(f"  {lang}: {count}")
    
    # Check for Python-specific results
    python_files = [row for row in all_rows if row["file_name"].endswith(".py")]
    print(f"\nPython-specific results: {len(python_files)} files")
    if python_files:
        python_cwes = {}
        for row in python_files:
            cwe = row["vul_type"]
            python_cwes[cwe] = python_cwes.get(cwe, 0) + 1
        print("Python CWE distribution:")
        for cwe, count in sorted(python_cwes.items(), key=lambda x: x[1], reverse=True)[:5]:
            print(f"  {cwe}: {count}")

if __name__ == "__main__":
    main()