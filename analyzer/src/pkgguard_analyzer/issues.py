"""Builds UI-ready code issues: exact file and lines, severity, plain-English explanation and the real code.

Merges rule findings, AI evidence and full-audit worker items that point at the same place. Code excerpts are
read from the unpacked package, so they must be built before the scan folder is deleted.
"""

from pathlib import Path, PurePosixPath

from pkgguard_analyzer.schema import (
    AIReview,
    CodeExcerpt,
    CodeIssue,
    ExcerptLine,
    Finding,
    FindingAssessment,
    IssueCategory,
    Severity,
)

CONTEXT_LINES = 3
MAX_HIGHLIGHT_LINES = 30
MAX_LINE_CHARS = 300
MAX_ISSUES = 60
MERGE_DISTANCE = 2
SEVERITY_RANK = {Severity.HIGH: 0, Severity.MEDIUM: 1, Severity.LOW: 2}

WHY_IT_MATTERS = {
    "metadata.install_script": "This command runs automatically during npm install, before any code is imported. Malware most often starts here.",
    "metadata.manifest_mismatch": "The install scripts inside the downloaded package differ from what npm shows, a trick to hide what really runs.",
    "code.exfiltration": "This code reads secrets or machine details and can send data over the network. That combination is how credentials get stolen.",
    "code.decode_and_run": "Hidden data is decoded and then run as code, a common way to hide a malicious payload.",
    "code.install_download_exec": "During install this code downloads something and runs programs. Normal for some build tools, dangerous if the source isn't trusted.",
    "code.install_network": "This code makes network requests while the package is being installed.",
    "code.exec": "Runs system commands, which can do anything your user account can do.",
    "code.dynamic_code": "Builds and runs code at runtime (eval, Function or vm), which hides what actually executes.",
    "code.env_dump": "Reads every environment variable at once, including any tokens or passwords stored there.",
    "code.sensitive_path": "Refers to a file that usually holds secrets such as keys, tokens or credentials.",
    "code.raw_ip": "Contacts a hard-coded IP address instead of a domain name, which is common in malware.",
    "code.hex_escapes": "Text is hidden behind hex escape sequences, a common way to disguise strings like URLs or commands.",
    "code.encoded_blob": "A large block of encoded data that could hide a payload.",
    "code.executable": "A precompiled program that can't be reviewed like source code.",
    "code.pattern.discord_webhook": "Discord webhooks are a popular way for malware to send stolen data to an attacker.",
    "code.pattern.telegram_bot_api": "Telegram bots are a popular way for malware to send stolen data to an attacker.",
    "code.pattern.request_capture_service": "Request-capture services collect whatever is sent to them and are often used to receive stolen data.",
    "code.pattern.crypto_miner": "Cryptocurrency mining code uses your machine's resources for someone else's profit.",
    "code.pattern.reverse_shell": "A reverse shell gives an attacker remote control of the machine.",
    "code.pattern.pipe_to_shell": "Downloading a script and running it immediately means running code nobody reviewed.",
    "code.pattern.powershell_encoded": "Encoded PowerShell commands hide what is being run.",
    "code.pattern.javascript_obfuscator": "The code is deliberately scrambled so humans and tools can't easily read it.",
    "code.pattern.llm_prompt_injection": "This text tries to talk AI security reviewers into ignoring the code, which is itself a strong warning sign.",
}

CATEGORY_BY_RULE = {
    "metadata.install_script": IssueCategory.INSTALL_SCRIPT,
    "metadata.manifest_mismatch": IssueCategory.INSTALL_SCRIPT,
    "code.exfiltration": IssueCategory.SECRET_THEFT,
    "code.decode_and_run": IssueCategory.HIDDEN_CODE,
    "code.install_download_exec": IssueCategory.COMMANDS,
    "code.install_network": IssueCategory.NETWORK,
    "code.exec": IssueCategory.COMMANDS,
    "code.dynamic_code": IssueCategory.HIDDEN_CODE,
    "code.env_dump": IssueCategory.SECRETS_ACCESS,
    "code.sensitive_path": IssueCategory.SECRETS_ACCESS,
    "code.raw_ip": IssueCategory.NETWORK,
    "code.hex_escapes": IssueCategory.HIDDEN_CODE,
    "code.encoded_blob": IssueCategory.HIDDEN_CODE,
    "code.executable": IssueCategory.BINARY,
    "code.pattern.discord_webhook": IssueCategory.SECRET_THEFT,
    "code.pattern.telegram_bot_api": IssueCategory.SECRET_THEFT,
    "code.pattern.request_capture_service": IssueCategory.SECRET_THEFT,
    "code.pattern.crypto_miner": IssueCategory.MINING,
    "code.pattern.reverse_shell": IssueCategory.REMOTE_CONTROL,
    "code.pattern.pipe_to_shell": IssueCategory.COMMANDS,
    "code.pattern.powershell_encoded": IssueCategory.COMMANDS,
    "code.pattern.javascript_obfuscator": IssueCategory.HIDDEN_CODE,
    "code.pattern.llm_prompt_injection": IssueCategory.PROMPT_INJECTION,
}

KEYWORD_CATEGORIES = (
    (("prompt injection", "ai reviewer"), IssueCategory.PROMPT_INJECTION),
    (("exfiltrat", "steal", "sends token", "send token", "credential theft"), IssueCategory.SECRET_THEFT),
    (("reverse shell", "remote control", "backdoor"), IssueCategory.REMOTE_CONTROL),
    (("miner", "mining"), IssueCategory.MINING),
    (("eval", "function(", "new function", "obfuscat", "base64", "decode", "hex"), IssueCategory.HIDDEN_CODE),
    (("token", "secret", "password", "credential", "process.env", ".npmrc", "ssh", "env var"), IssueCategory.SECRETS_ACCESS),
    (("child_process", "spawn", "exec", "command", "shell"), IssueCategory.COMMANDS),
    (("http", "fetch", "dns", "network", "socket", "request", "url", "webhook"), IssueCategory.NETWORK),
)


def category_from_text(text: str, title: str = "") -> IssueCategory:
    """The short title is the clearest signal, so it's checked before the longer explanation."""
    for candidate in (title, text):
        lowered = candidate.lower()
        if match := next((category for keywords, category in KEYWORD_CATEGORIES if any(k in lowered for k in keywords)), None):
            return match
    return IssueCategory.OTHER


class PackageFiles:
    """Reads package files safely (inside the package folder only) and caches their lines."""

    def __init__(self, root: Path):
        self.root = root.resolve()
        self._cache: dict[str, list[str] | None] = {}

    def lines(self, path: str) -> list[str] | None:
        if path not in self._cache:
            candidate = PurePosixPath(path)
            target = (self.root / candidate).resolve()
            if candidate.is_absolute() or ".." in candidate.parts or not target.is_relative_to(self.root) or not target.is_file():
                self._cache[path] = None
            else:
                data = target.read_bytes()
                self._cache[path] = None if b"\x00" in data[:8000] else data.decode("utf-8", "replace").split("\n")
        return self._cache[path]


def _clip(text: str, focus: str | None) -> tuple[str, bool]:
    if len(text) <= MAX_LINE_CHARS:
        return text, False
    column = text.find(focus[:40]) if focus else -1
    start = max(0, column - MAX_LINE_CHARS // 3) if column >= 0 else 0
    return text[start : start + MAX_LINE_CHARS], True


def build_excerpt(lines: list[str], start: int, end: int, focus: str | None = None) -> CodeExcerpt:
    end = min(max(end, start), start + MAX_HIGHLIGHT_LINES - 1, len(lines))
    first, last = max(1, start - CONTEXT_LINES), min(len(lines), end + CONTEXT_LINES)
    rows = []
    for number in range(first, last + 1):
        highlighted = start <= number <= end
        text, clipped = _clip(lines[number - 1], focus if highlighted else None)
        rows.append(ExcerptLine(number=number, text=text, highlighted=highlighted, clipped=clipped))
    return CodeExcerpt(start_line=first, end_line=last, highlight_start=start, highlight_end=end, lines=rows)


def _find_script_line(lines: list[str], hook: str) -> int | None:
    return next((i for i, line in enumerate(lines, 1) if f'"{hook}"' in line), None)


class _IssueBuilder:
    def __init__(self, files: PackageFiles, install_files: set[str]):
        self.files = files
        self.install_files = install_files
        self.issues: list[CodeIssue] = []

    def add(
        self,
        *,
        file: str,
        line: int | None,
        end_line: int | None,
        severity: Severity,
        category: IssueCategory,
        title: str,
        source: str,
        why: str | None = None,
        analysis: str | None = None,
        rule_id: str | None = None,
        install_time: bool = False,
        focus: str | None = None,
    ) -> None:
        lines = self.files.lines(file)
        if lines is None:
            return  # the file doesn't exist in the package (or is binary): never show made-up locations
        if line is not None and not 1 <= line <= len(lines):
            line = end_line = None
        if line is not None and (end_line is None or end_line < line):
            end_line = line

        for issue in self.issues:
            if issue.file == file and self._near(issue, line, end_line):
                self._merge(issue, severity, source, why, analysis, rule_id, line, end_line)
                return

        issue = CodeIssue(
            id="",
            file=file,
            line_start=line,
            line_end=end_line,
            severity=severity,
            category=category,
            title=title,
            why_it_matters=why,
            analysis=analysis,
            sources=[source],
            rule_ids=[rule_id] if rule_id else [],
            install_time=install_time or file in self.install_files,
            excerpt=build_excerpt(lines, line, end_line, focus) if line is not None else None,
        )
        self.issues.append(issue)

    @staticmethod
    def _near(issue: CodeIssue, line: int | None, end_line: int | None) -> bool:
        if line is None or issue.line_start is None:
            return line is None and issue.line_start is None
        return line <= (issue.line_end or issue.line_start) + MERGE_DISTANCE and (end_line or line) >= issue.line_start - MERGE_DISTANCE

    def _merge(self, issue: CodeIssue, severity, source, why, analysis, rule_id, line, end_line) -> None:
        if SEVERITY_RANK[severity] < SEVERITY_RANK[issue.severity]:
            issue.severity = severity
        if source not in issue.sources:
            issue.sources.append(source)
        if rule_id and rule_id not in issue.rule_ids:
            issue.rule_ids.append(rule_id)
        issue.why_it_matters = issue.why_it_matters or why
        if analysis and analysis != issue.analysis:
            issue.analysis = f"{issue.analysis}\n\n{analysis}" if issue.analysis else analysis
        # Widen the highlighted range to cover both reports, and refresh the excerpt.
        if line is not None and issue.line_start is not None:
            start, end = min(line, issue.line_start), max(end_line or line, issue.line_end or issue.line_start)
            if (start, end) != (issue.line_start, issue.line_end):
                issue.line_start, issue.line_end = start, end
                issue.excerpt = build_excerpt(self.files.lines(issue.file), start, end)


def _assessment_for(assessments: list[FindingAssessment], finding: Finding) -> FindingAssessment | None:
    exact = [a for a in assessments if a.rule_id == finding.rule_id and a.file == finding.file]
    loose = [a for a in assessments if a.rule_id == finding.rule_id and not a.file]
    return (exact or loose or [None])[0]


def build_code_issues(files_dir: Path, findings: list[Finding], ai: AIReview | None, install_files: list[str] | None = None) -> list[CodeIssue]:
    builder = _IssueBuilder(PackageFiles(files_dir), set(install_files or []))
    assessments = ai.finding_assessments if ai else []

    for finding in findings:
        if not finding.file:
            continue
        line = finding.line
        if finding.rule_id == "metadata.install_script" and line is None:
            package_lines = builder.files.lines(finding.file) or []
            hook = finding.title.split("'")[1] if "'" in finding.title else ""
            line = _find_script_line(package_lines, hook) if hook else None
        assessment = _assessment_for(assessments, finding)
        builder.add(
            file=finding.file,
            line=line,
            end_line=line,
            severity=finding.severity,
            category=CATEGORY_BY_RULE.get(finding.rule_id, IssueCategory.OTHER),
            title=finding.title,
            source="rules",
            why=WHY_IT_MATTERS.get(finding.rule_id),
            analysis=assessment.explanation if assessment else None,
            rule_id=finding.rule_id,
            install_time=finding.install_time,
            focus=finding.snippet,
        )
        if assessment and builder.issues:
            for issue in builder.issues:
                if finding.rule_id in issue.rule_ids:
                    issue.ai_assessment = assessment.assessment

    if ai is not None:
        for evidence in ai.evidence:
            if evidence.severity is None:
                continue
            title = evidence.title or evidence.explanation.split(". ")[0][:80]
            builder.add(
                file=evidence.file,
                line=evidence.line,
                end_line=evidence.end_line,
                severity=evidence.severity,
                category=category_from_text(evidence.explanation, title),
                title=title,
                source="ai",
                analysis=evidence.explanation,
            )
        for part in ai.worker_reports:
            for item in part.report.suspicious_items if part.report else []:
                if item.severity == Severity.LOW:
                    continue
                builder.add(
                    file=item.file,
                    line=item.line,
                    end_line=item.end_line,
                    severity=item.severity,
                    category=category_from_text(item.explanation, item.behavior),
                    title=item.behavior[:80],
                    source="ai-worker",
                    analysis=item.explanation,
                )

    issues = sorted(builder.issues, key=lambda i: (SEVERITY_RANK[i.severity], not i.install_time, i.file, i.line_start or 0))[:MAX_ISSUES]
    for number, issue in enumerate(issues, 1):
        issue.id = f"issue-{number}"
    return issues
