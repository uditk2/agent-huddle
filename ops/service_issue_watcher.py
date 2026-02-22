#!/usr/bin/env python3
from __future__ import annotations

import argparse
import datetime as dt
import difflib
import hashlib
import json
import os
import pathlib
import re
import subprocess
import sys
import textwrap
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Any

UTC = dt.timezone.utc
DEFAULT_ERROR_REGEX = [
    r"(?i)\b(error|fatal|critical|panic|exception|traceback|unhandled|segfault)\b",
    r"(?i)\b(econnreset|connection reset|timed? out|timeout)\b",
]
DEFAULT_LOG_FETCH_CMD = 'journalctl -u nse-insights.service --since "$SINCE_ISO" --no-pager -o short-iso'
SERVICE_ERROR_PREFIX = "[service-error]"


@dataclass
class ErrorEvent:
    summary: str
    sample: str
    fingerprint: str
    matched_regex: str


def now_iso() -> str:
    return dt.datetime.now(UTC).replace(microsecond=0).isoformat()


def run_cmd(args: list[str], *, cwd: pathlib.Path | None = None, env: dict[str, str] | None = None) -> str:
    proc = subprocess.run(
        args,
        cwd=str(cwd) if cwd else None,
        env=env,
        text=True,
        capture_output=True,
        check=False,
    )
    if proc.returncode != 0:
        raise RuntimeError(f"Command failed ({proc.returncode}): {' '.join(args)}\n{proc.stderr.strip()}")
    return proc.stdout


def parse_repo_from_remote(remote: str) -> str | None:
    remote = remote.strip()
    m = re.search(r"github\.com[:/]([^/]+/[^/.]+)(?:\.git)?$", remote)
    return m.group(1) if m else None


def resolve_repo(repo_root: pathlib.Path) -> str:
    explicit = os.environ.get("GITHUB_REPO", "").strip()
    if explicit:
        return explicit
    remote = run_cmd(["git", "-C", str(repo_root), "remote", "get-url", "origin"]).strip()
    parsed = parse_repo_from_remote(remote)
    if not parsed:
        raise RuntimeError(f"Unable to parse GitHub repo from origin remote: {remote}")
    return parsed


def load_state(state_file: pathlib.Path) -> dict[str, Any]:
    if not state_file.exists():
        return {"last_checked_iso": None, "fingerprints": {}}
    try:
        return json.loads(state_file.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return {"last_checked_iso": None, "fingerprints": {}}


def save_state(state_file: pathlib.Path, state: dict[str, Any]) -> None:
    state_file.parent.mkdir(parents=True, exist_ok=True)
    state_file.write_text(json.dumps(state, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def normalize_for_fingerprint(text: str) -> str:
    line = text.strip()
    line = re.sub(r"^\d{4}-\d{2}-\d{2}[T\s].*?\s", "", line)
    line = re.sub(r"0x[0-9a-fA-F]+", "<hex>", line)
    line = re.sub(r"\b\d+\b", "<num>", line)
    line = re.sub(r"\s+", " ", line)
    return line.lower()


def make_fingerprint(text: str) -> str:
    canonical = normalize_for_fingerprint(text)
    return hashlib.sha1(canonical.encode("utf-8")).hexdigest()[:16]


def collect_errors(log_text: str, regexes: list[str]) -> list[ErrorEvent]:
    compiled = [re.compile(x) for x in regexes]
    events: list[ErrorEvent] = []
    seen: set[str] = set()

    for raw_line in log_text.splitlines():
        line = raw_line.strip()
        if not line:
            continue

        matched = None
        for pattern in compiled:
            if pattern.search(line):
                matched = pattern.pattern
                break
        if not matched:
            continue

        fingerprint = make_fingerprint(line)
        if fingerprint in seen:
            continue
        seen.add(fingerprint)

        summary = line
        if len(summary) > 140:
            summary = summary[:137] + "..."

        events.append(
            ErrorEvent(
                summary=summary,
                sample=line,
                fingerprint=fingerprint,
                matched_regex=matched,
            )
        )

    return events


def gh_issue_list(repo: str, limit: int = 100) -> list[dict[str, Any]]:
    cmd = [
        "gh",
        "issue",
        "list",
        "-R",
        repo,
        "--state",
        "open",
        "--limit",
        str(limit),
        "--search",
        f"{SERVICE_ERROR_PREFIX} in:title",
        "--json",
        "number,title,body,url",
    ]
    out = run_cmd(cmd)
    try:
        payload = json.loads(out)
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"Unable to decode gh issue list output: {exc}") from exc
    if not isinstance(payload, list):
        return []
    return payload


def heuristic_duplicate(event: ErrorEvent, issues: list[dict[str, Any]]) -> int | None:
    summary_norm = normalize_for_fingerprint(event.summary)
    for issue in issues:
        body = issue.get("body") or ""
        if f"Fingerprint: {event.fingerprint}" in body:
            return int(issue["number"])

    for issue in issues:
        title = str(issue.get("title") or "")
        title_norm = normalize_for_fingerprint(title.replace(SERVICE_ERROR_PREFIX, ""))
        similarity = difflib.SequenceMatcher(None, summary_norm, title_norm).ratio()
        if similarity >= 0.92:
            return int(issue["number"])
    return None


def llm_duplicate(
    event: ErrorEvent,
    issues: list[dict[str, Any]],
    *,
    model: str,
    api_url: str,
    api_key: str,
    timeout_sec: int = 20,
) -> int | None:
    if not issues:
        return None

    prompt = {
        "candidate": {
            "summary": event.summary,
            "fingerprint": event.fingerprint,
            "sample": event.sample,
        },
        "issues": [
            {
                "number": issue.get("number"),
                "title": issue.get("title"),
                "body": (issue.get("body") or "")[:500],
            }
            for issue in issues
        ],
        "instructions": (
            "Return strict JSON only with keys duplicate_issue_number (number or null), "
            "confidence (0-1), reason (short string)."
        ),
    }

    req_body = {
        "model": model,
        "temperature": 0,
        "response_format": {"type": "json_object"},
        "messages": [
            {
                "role": "system",
                "content": "You dedupe production incidents against existing GitHub issues.",
            },
            {
                "role": "user",
                "content": json.dumps(prompt, ensure_ascii=True),
            },
        ],
    }

    req = urllib.request.Request(
        api_url,
        data=json.dumps(req_body).encode("utf-8"),
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {api_key}",
        },
        method="POST",
    )

    try:
        with urllib.request.urlopen(req, timeout=timeout_sec) as resp:
            content = resp.read().decode("utf-8")
    except urllib.error.URLError as exc:
        raise RuntimeError(f"LLM dedupe request failed: {exc}") from exc

    try:
        payload = json.loads(content)
        raw_text = payload["choices"][0]["message"]["content"]
    except Exception as exc:  # noqa: BLE001
        raise RuntimeError(f"Unexpected LLM response format: {content[:500]}") from exc

    try:
        verdict = json.loads(raw_text)
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"LLM response content is not JSON: {raw_text[:200]}") from exc

    issue_no = verdict.get("duplicate_issue_number")
    if isinstance(issue_no, int):
        known = {int(x.get("number")) for x in issues if x.get("number") is not None}
        if issue_no in known:
            return issue_no
    return None


def build_issue_body(event: ErrorEvent, service_name: str, source_cmd: str) -> str:
    return textwrap.dedent(
        f"""
        Automated incident report from local issue-watcher.

        - Service: `{service_name}`
        - Detected at (UTC): `{now_iso()}`
        - Fingerprint: `{event.fingerprint}`
        - Matched regex: `{event.matched_regex}`
        - Log source command: `{source_cmd}`

        Sample log line:

        ```text
        {event.sample}
        ```

        If this keeps recurring, keep this issue open and track mitigation updates here.
        """
    ).strip()


def gh_create_issue(repo: str, title: str, body: str) -> str:
    out = run_cmd(["gh", "issue", "create", "-R", repo, "--title", title, "--body", body])
    return out.strip()


def parse_issue_number(issue_url: str) -> int | None:
    match = re.search(r"/issues/(\d+)$", issue_url.strip())
    if not match:
        return None
    return int(match.group(1))


def run_cycle(args: argparse.Namespace) -> int:
    repo_root = pathlib.Path(args.repo_root).resolve()
    state_file = pathlib.Path(args.state_file).resolve()
    state = load_state(state_file)
    repo = resolve_repo(repo_root)

    now = now_iso()
    since_iso = state.get("last_checked_iso")
    if not since_iso:
        since_iso = (dt.datetime.now(UTC) - dt.timedelta(minutes=args.bootstrap_minutes)).replace(microsecond=0).isoformat()

    env = os.environ.copy()
    env["SINCE_ISO"] = since_iso
    env["NOW_ISO"] = now

    source_cmd = args.log_fetch_cmd
    log_text = run_cmd(["bash", "-lc", source_cmd], cwd=repo_root, env=env)
    events = collect_errors(log_text, args.error_regex)

    skip_github = args.skip_github
    if not skip_github:
        try:
            run_cmd(["gh", "auth", "status"])
        except Exception as exc:  # noqa: BLE001
            print(f"WARN: gh auth unavailable; running in skip-github mode: {exc}", file=sys.stderr)
            skip_github = True

    issues: list[dict[str, Any]] = []
    if not skip_github:
        try:
            issues = gh_issue_list(repo, limit=args.issue_scan_limit)
        except Exception as exc:  # noqa: BLE001
            if args.dry_run:
                print(f"WARN: gh issue list unavailable in dry-run: {exc}", file=sys.stderr)
                issues = []
            else:
                raise

    fingerprints = state.setdefault("fingerprints", {})
    created = 0
    deduped = 0

    api_url = os.environ.get("DEDUPE_API_URL", "").strip()
    api_key = os.environ.get("DEDUPE_API_KEY", "").strip()
    model = os.environ.get("DEDUPE_MODEL", "sqen").strip() or "sqen"

    for event in events:
        known = fingerprints.get(event.fingerprint)
        if known and known.get("issue_number"):
            deduped += 1
            known["last_seen_iso"] = now
            known["occurrences"] = int(known.get("occurrences", 0)) + 1
            continue

        duplicate_issue_no = heuristic_duplicate(event, issues)
        if duplicate_issue_no is None and api_url and api_key:
            try:
                duplicate_issue_no = llm_duplicate(
                    event,
                    issues,
                    model=model,
                    api_url=api_url,
                    api_key=api_key,
                )
            except Exception as exc:  # noqa: BLE001
                print(f"WARN: LLM dedupe failed for {event.fingerprint}: {exc}", file=sys.stderr)

        if duplicate_issue_no is not None:
            deduped += 1
            fingerprints[event.fingerprint] = {
                "issue_number": duplicate_issue_no,
                "last_seen_iso": now,
                "occurrences": int((known or {}).get("occurrences", 0)) + 1,
            }
            continue

        title = f"{SERVICE_ERROR_PREFIX} {args.service_name}: {event.summary}"
        body = build_issue_body(event, args.service_name, source_cmd)
        created_issue_number: int | None = None

        if args.dry_run or skip_github:
            print(f"DRY_RUN create issue: {title}")
            print(body)
        else:
            issue_url = gh_create_issue(repo, title, body)
            print(f"Created issue: {issue_url}")
            created += 1
            issues = gh_issue_list(repo, limit=args.issue_scan_limit)
            created_issue_number = parse_issue_number(issue_url)

        fingerprints[event.fingerprint] = {
            "issue_number": None if args.dry_run else created_issue_number,
            "last_seen_iso": now,
            "occurrences": int((known or {}).get("occurrences", 0)) + 1,
        }

    state["last_checked_iso"] = now
    save_state(state_file, state)

    print(
        json.dumps(
            {
                "repo": repo,
                "service": args.service_name,
                "since": since_iso,
                "checked_at": now,
                "events_found": len(events),
                "issues_created": created,
                "deduped": deduped,
                "dry_run": args.dry_run,
                "skip_github": skip_github,
                "dedupe_model": model,
                "llm_enabled": bool(api_url and api_key),
            },
            sort_keys=True,
        )
    )
    return 0


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Monitor service logs and open deduped GitHub issues.")
    parser.add_argument("--repo-root", default=str(pathlib.Path(__file__).resolve().parents[1]))
    parser.add_argument(
        "--state-file",
        default=str(pathlib.Path(__file__).resolve().parent / ".issue_watcher_state.json"),
    )
    parser.add_argument("--service-name", default=os.environ.get("WATCH_SERVICE_NAME", "nse-insights.service"))
    parser.add_argument("--log-fetch-cmd", default=os.environ.get("LOG_FETCH_CMD", DEFAULT_LOG_FETCH_CMD))
    parser.add_argument("--issue-scan-limit", type=int, default=100)
    parser.add_argument("--bootstrap-minutes", type=int, default=10)
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--skip-github", action="store_true")
    parser.add_argument("--error-regex", action="append", default=[])

    args = parser.parse_args(argv)
    if not args.error_regex:
        args.error_regex = DEFAULT_ERROR_REGEX.copy()
    return args


def main(argv: list[str]) -> int:
    args = parse_args(argv)
    try:
        return run_cycle(args)
    except Exception as exc:  # noqa: BLE001
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
