#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
github_cwe_crawler.py (v0.2)

- Fix: commit detail JSON has no 'repository' -> parse owner/repo from URL
- Filter: skip CVE meta repos, non-source files
- Extract: old/new contents around changed hunks (function-level when possible)
- Map: CVE -> CWE via NVD 2.0 API
- Output: CSV compatible with safecoder_training_data.csv
"""

import os
import re
import csv
import sys
import time
import base64
import argparse
from typing import Dict, List, Optional, Tuple
import requests
from tqdm import tqdm

GITHUB_API = "https://api.github.com"
NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"

GITHUB_TOKEN = os.getenv("GITHUB_TOKEN", "")
HEADERS = {
    "Accept": "application/vnd.github+json",
    "User-Agent": "cwe-fix-crawler/0.2",
}
if GITHUB_TOKEN:
    HEADERS["Authorization"] = f"Bearer {GITHUB_TOKEN}"

# 메타 저장소/잡음 저장소 제외
SKIP_REPOS = {
    "CVEProject/cvelistV5",
    "CVEProject/cvelist",  # 구버전
}
# 파일 확장자 화이트리스트 (필요시 추가)
ALLOWED_EXTS = {
    ".c", ".cc", ".cpp", ".h", ".hpp",
    ".java", ".kt",
    ".py",
    ".js", ".jsx", ".ts", ".tsx",
    ".go",
    ".rb",
    ".php",
    ".rs",
    ".cs",
    ".swift",
}

# 간단한 언어 추정 (파일 확장자 기반)
def guess_lang_by_ext(path: str) -> str:
    ext = path[path.rfind(".") :].lower() if "." in path else ""
    return {
        ".py": "python",
        ".go": "go",
        ".js": "javascript",
        ".jsx": "javascript",
        ".ts": "typescript",
        ".tsx": "typescript",
        ".java": "java",
        ".kt": "kotlin",
        ".c": "c",
        ".cc": "cpp",
        ".cpp": "cpp",
        ".h": "c",
        ".hpp": "cpp",
        ".rb": "ruby",
        ".php": "php",
        ".rs": "rust",
        ".cs": "csharp",
        ".swift": "swift",
    }.get(ext, "unknown")

def ext_allowed(path: str) -> bool:
    dot = path.rfind(".")
    if dot == -1:
        return False
    return path[dot:].lower() in ALLOWED_EXTS

def parse_owner_repo_from_commit_url(commit_api_url: str) -> Tuple[Optional[str], Optional[str]]:
    # e.g. https://api.github.com/repos/OWNER/REPO/commits/SHA
    try:
        tail = commit_api_url.split("/repos/", 1)[1]  # OWNER/REPO/commits/SHA
        owner, repo = tail.split("/", 2)[:2]
        return owner, repo
    except Exception:
        return None, None

def search_commits(query: str, max_results: int) -> List[Dict]:
    """
    Use GitHub commit search. We post-filter results by file extensions later.
    """
    url = f"{GITHUB_API}/search/commits"
    session = requests.Session()
    session.headers.update(HEADERS)
    params = {
        "q": query,
        "sort": "committer-date",
        "order": "desc",
        "per_page": 100,
    }
    items: List[Dict] = []
    while True:
        r = session.get(url, params=params, timeout=30)
        if r.status_code == 422 and "query is too long" in r.text.lower():
            raise RuntimeError("GitHub: Query too long or invalid for commit search.")
        r.raise_for_status()
        data = r.json()
        batch = data.get("items", [])
        items.extend(batch)
        if len(items) >= max_results:
            return items[:max_results]
        # pagination
        link = r.headers.get("Link", "")
        next_url = None
        for part in link.split(","):
            if 'rel="next"' in part:
                next_url = part[part.find("<")+1:part.find(">")]
        if not next_url:
            break
        url = next_url
        params = {}  # already encoded in next_url
        time.sleep(0.7)
    return items[:max_results]

def get_json(url: str, session: requests.Session) -> Dict:
    r = session.get(url, timeout=30)
    r.raise_for_status()
    return r.json()

def get_file_content(owner: str, repo: str, path: str, ref: str, session: requests.Session) -> Optional[str]:
    # Prefer raw for performance
    url = f"{GITHUB_API}/repos/{owner}/{repo}/contents/{path}"
    headers = dict(HEADERS)
    headers["Accept"] = "application/vnd.github.raw"
    r = session.get(url, params={"ref": ref}, headers=headers, timeout=30)
    if r.status_code == 200:
        return r.text
    # Fallback to JSON (base64)
    headers["Accept"] = "application/vnd.github+json"
    r = session.get(url, params={"ref": ref}, headers=headers, timeout=30)
    if r.status_code == 200 and r.headers.get("Content-Type", "").startswith("application/json"):
        j = r.json()
        if j.get("encoding") == "base64" and "content" in j:
            try:
                return base64.b64decode(j["content"]).decode("utf-8", errors="replace")
            except Exception:
                return None
    return None

HUNK_RE = re.compile(r"@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@")
def parse_new_hunks(patch: str) -> List[Tuple[int, int]]:
    hunks = []
    for line in patch.splitlines():
        if line.startswith("@@"):
            m = HUNK_RE.search(line)
            if m:
                new_start = int(m.group(3))
                new_len = int(m.group(4) or "1")
                hunks.append((new_start, new_len))
    return hunks

# 함수명/스니펫 추출(간단 휴리스틱)
FUNC_RE = {
    "python": re.compile(r"^\s*def\s+([A-Za-z_]\w*)\s*\(", re.M),
    "go": re.compile(r"^\s*func\s+([A-Za-z_]\w*)\s*\(", re.M),
    "javascript": re.compile(r"^\s*(?:function\s+([A-Za-z_]\w*)\s*\(|([A-Za-z_]\w*)\s*=\s*function\s*\(|([A-Za-z_]\w*)\s*:\s*function\s*\()", re.M),
    "typescript": re.compile(r"^\s*(?:function\s+([A-Za-z_]\w*)\s*\()", re.M),
    "java": re.compile(r"^\s*(?:public|protected|private|static|\s)+\s*[\w\<\>\[\]]+\s+([A-Za-z_]\w*)\s*\(", re.M),
    "c": re.compile(r"^\s*[A-Za-z_][\w\*\s]*\s+([A-Za-z_]\w*)\s*\([^;]*\)\s*\{", re.M),
    "cpp": re.compile(r"^\s*[A-Za-z_][\w\*\s:<>,]*\s+([A-Za-z_]\w*)\s*\([^;]*\)\s*\{", re.M),
    "ruby": re.compile(r"^\s*def\s+([A-Za-z_]\w*)", re.M),
    "php": re.compile(r"^\s*function\s+([A-Za-z_]\w*)\s*\(", re.M),
    "csharp": re.compile(r"^\s*(?:public|protected|private|static|\s)+\s*[\w\<\>\[\]]+\s+([A-Za-z_]\w*)\s*\(", re.M),
    "swift": re.compile(r"^\s*func\s+([A-Za-z_]\w*)\s*\(", re.M),
}

def nearest_function_name(lang: str, code: str, around_line: int) -> Optional[str]:
    reg = FUNC_RE.get(lang)
    if not reg:
        return None
    names = []
    for m in reg.finditer(code):
        # 라인 번호 계산
        line_no = code.count("\n", 0, m.start()) + 1
        names.append((line_no, m.group(1) if m.group(1) else (m.group(2) or m.group(3))))
    if not names:
        return None
    # around_line 직전 가장 가까운 함수
    cand = [t for t in names if t[0] <= around_line]
    return cand[-1][1] if cand else names[0][1]

def slice_function_block(lang: str, code: str, func_name: Optional[str], around_line: int, max_lines: int = 0) -> str:
    lines = code.splitlines()
    n = len(lines)
    if lang == "python":
        # 들여쓰기 블록
        start = None
        for i in range(min(around_line-1, n-1), -1, -1):
            if re.match(rf"^\s*def\s+{re.escape(func_name or '')}\s*\(", lines[i]) or (func_name is None and lines[i].lstrip().startswith("def ")):
                start = i
                indent = len(lines[i]) - len(lines[i].lstrip(" "))
                j = i + 1
                while j < n and j - i < max_lines:
                    if lines[j].strip() == "":
                        j += 1
                        continue
                    this_indent = len(lines[j]) - len(lines[j].lstrip(" "))
                    if this_indent <= indent:
                        break
                    j += 1
                return "\n".join(lines[i:j])
        # fallback: around line window
        s = max(around_line-10, 0); e = min(around_line+30, n, s+max_lines)
        return "\n".join(lines[s:e])
    else:
        # 중괄호 블록 (대강)
        # 함수 시그니처 라인부터 괄호 짝 맞추기
        sig = None
        for i in range(min(around_line-1, n-1), -1, -1):
            if func_name and re.search(rf"\b{re.escape(func_name)}\s*\(", lines[i]):
                sig = i; break
            if not func_name and re.search(r"\)\s*\{", lines[i]):
                sig = i; break
        if sig is not None:
            depth = 0
            started = False
            buf = []
            for j in range(sig, min(n, sig + max_lines)):
                buf.append(lines[j])
                depth += lines[j].count("{") - lines[j].count("}")
                if "{" in lines[j]:
                    started = True
                if started and depth <= 0:
                    break
            return "\n".join(buf)
        # fallback
        s = max(around_line-15, 0); e = min(around_line+35, n, s+max_lines)
        return "\n".join(lines[s:e])

CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.I)
CWE_RE = re.compile(r"CWE-\d+", re.I)

def extract_cves(text: str) -> List[str]:
    return sorted(set(m.group(0).upper() for m in CVE_RE.finditer(text or "")))

def extract_cwes(text: str) -> List[str]:
    return sorted(set(m.group(0).upper() for m in CWE_RE.finditer(text or "")))

def nvd_lookup_cwe(cve_id: str, session: requests.Session) -> Optional[str]:
    try:
        r = session.get(NVD_API, params={"cveId": cve_id}, timeout=30)
        r.raise_for_status()
        j = r.json()
        vulns = j.get("vulnerabilities") or []
        if not vulns:
            return None
        weaknesses = vulns[0].get("cve", {}).get("weaknesses") or []
        if not weaknesses:
            return None
        descs = weaknesses[0].get("description") or []
        if not descs:
            return None
        val = descs[0].get("value", "")
        m = re.search(r"CWE-\d+", val)
        return m.group(0).lower() if m else None
    except Exception:
        return None

def build_prompt(lang: str, cwe: Optional[str], file_name: str) -> str:
    if cwe:
        return f"Write a {lang} function that avoids {cwe.upper()} based on secure coding practices, using {file_name} as context."
    return f"Write a {lang} function with secure input handling and correct logic, using {file_name} as context."

def process_commit_item(item: Dict, out_rows: List[Dict], train_split: float, session: requests.Session, verbose_log: List[str]) -> None:
    commit_api_url = item["url"]
    html_url = item.get("html_url", "")
    repo_fullname = None
    if "repository" in item and item["repository"] and "full_name" in item["repository"]:
        repo_fullname = item["repository"]["full_name"]
    if not repo_fullname:
        owner, repo = parse_owner_repo_from_commit_url(commit_api_url)
        repo_fullname = f"{owner}/{repo}" if owner and repo else None

    if not repo_fullname or repo_fullname in SKIP_REPOS:
        verbose_log.append(f"skip (meta repo): {repo_fullname}  {html_url or commit_api_url}")
        return

    owner, repo = repo_fullname.split("/")
    commit = get_json(commit_api_url, session)
    if not commit.get("files"):
        verbose_log.append(f"skip (no files): {html_url}")
        return

    parent_sha = None
    parents = commit.get("parents") or []
    if parents:
        parent_sha = parents[0].get("sha")

    cve_ids = extract_cves(commit.get("commit", {}).get("message", ""))
    cwe_id = None
    for cid in cve_ids:
        cwe_id = nvd_lookup_cwe(cid, session)
        if cwe_id:
            break
    if not cwe_id:
        cwe_id = "unknown"

    for f in commit["files"]:
        filename = f.get("filename") or ""
        status = f.get("status")
        patch = f.get("patch")
        if status not in {"modified", "added", "changed"}:
            continue
        if not ext_allowed(filename):
            continue
        if not patch or not parent_sha:
            # added 파일은 부모에 없음 → 취약 코드 추출 불가 (스킵)
            verbose_log.append(f"skip (no patch or no parent): {repo_fullname} {filename}")
            continue

        # 파일 내용 (이전/이후)
        new_sha = commit.get("sha")
        new_code = get_file_content(owner, repo, filename, new_sha, session)
        old_code = get_file_content(owner, repo, filename, parent_sha, session)
        if not new_code or not old_code:
            verbose_log.append(f"skip (missing contents): {repo_fullname} {filename}")
            continue

        # hunk 기준으로 라인 근처 함수 추출
        hunks = parse_new_hunks(patch)
        if not hunks:
            verbose_log.append(f"skip (no hunks parsed): {repo_fullname} {filename}")
            continue

        lang = guess_lang_by_ext(filename)
        # 첫 번째 hunk 기준
        around_line = hunks[0][0]
        func_name_new = nearest_function_name(lang, new_code, around_line)
        fixed_snippet = slice_function_block(lang, new_code, func_name_new, around_line)
        vuln_snippet = slice_function_block(lang, old_code, func_name_new, around_line)

        # 데이터셋 행 구성 (safecoder_training_data.csv 형식)
        # 기존 파일에서 보듯 code == non_vulnerable_code 로 맞춤
        row = {
            "dataset": "train_sec-new-desc" if (hash((repo_fullname, filename, new_sha)) % 1000) / 1000.0 < train_split else "val_sec-new-desc",
            "func_name": func_name_new or "",
            "code": fixed_snippet,
            "prompts": build_prompt(lang, cwe_id if cwe_id != "unknown" else None, filename),
            "vulnerable_code": vuln_snippet,
            "non_vulnerable_code": fixed_snippet,
            "vul_type": cwe_id,
            "commit_link": commit.get("html_url") or html_url or commit_api_url,
            "file_name": filename,
        }
        out_rows.append(row)

def main():
    ap = argparse.ArgumentParser(description="Crawl GitHub for vulnerable/fixed code pairs.")
    ap.add_argument("--query", required=True, help='Search query for GitHub commits (e.g. \'CVE-2024 fix -org:CVEProject\')')
    ap.add_argument("--max-results", type=int, default=200)
    ap.add_argument("--output", default="my_dataset.csv")
    ap.add_argument("--train-split", type=float, default=0.9)
    args = ap.parse_args()

    if not GITHUB_TOKEN:
        print("WARNING: GITHUB_TOKEN not set. You will hit very low rate limits.", file=sys.stderr)

    items = search_commits(args.query, args.max_results)
    session = requests.Session()
    session.headers.update(HEADERS)

    rows: List[Dict] = []
    verbose_log: List[str] = []

    for it in tqdm(items, desc="Processing commits"):
        try:
            process_commit_item(it, rows, args.train_split, session, verbose_log)
            time.sleep(0.2)  # polite pacing
        except requests.HTTPError as e:
            verbose_log.append(f"HTTP error: {e} on {it.get('url')}")
        except Exception as e:
            verbose_log.append(f"Failed to process {it.get('url')}: {e}")

    # 출력
    fieldnames = ["dataset","func_name","code","prompts","vulnerable_code","non_vulnerable_code","vul_type","commit_link","file_name"]
    with open(args.output, "w", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fieldnames)
        w.writeheader()
        for r in rows:
            w.writerow(r)

    print(f"Wrote {len(rows)} rows to {args.output}")
    # 디버그 로그를 stderr로 출력
    if verbose_log:
        print("\n--- skipped/verbose ---", file=sys.stderr)
        for line in verbose_log[:200]:
            print(line, file=sys.stderr)

if __name__ == "__main__":
    main()
