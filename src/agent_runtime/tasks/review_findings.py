"""Report version 2: bounded, source-grounded review findings in plain prose.

Leaf module (stdlib only) so both the worker-side `accepted_text` and the parent adapter can
share one validator without import cycles. An empty findings list is allowed. Version 1 fact reports are validated elsewhere and
are never reinterpreted here.

Screening is conservative and deliberately limited: it restricts the character set, length and
shape of prose, rejects obvious secret/PII/error/source/path payloads and checks that the file,
line and hash reference the selected snapshots. It is not proof that a finding is correct and
not a universal secret or PII detector.
"""

import hashlib
import json
import re

REPORT_VERSION = 2
MAX_FINDINGS = 5
MIN_FIELD_CHARS = 20
MAX_FIELD_BYTES = 240
MAX_REPORT_BYTES = 5120
FIELDS = {"id", "problem", "impact", "suggested_fix", "file", "line", "sha256"}
IDENTITY = re.compile(r"F[1-9]")
# Single-line plain prose only; no markup, quotes, backslashes, URLs, paths or control characters.
PROSE = re.compile(r"[A-Za-z0-9][A-Za-z0-9 .,;:'!?()+\-_%*]*")
SECRET_WORDS = re.compile(
    r"password|passwd|secret|api[ _-]?key|token|bearer|credential|private key|authorization|ssn",
    re.IGNORECASE,
)
SECRET_SHAPES = re.compile(
    r"[A-Za-z0-9+_-]{24,}|[0-9a-fA-F]{16,}|\b(?:sk|pk|ghp|gho|xox[a-z]|AKIA)[-_A-Za-z0-9]{8,}"
)
PII_NUMBER = re.compile(r"\d(?:[ .-]?\d){6,}")
ERROR_TEXT = re.compile(
    r"traceback|exception|error:|errno|stack trace|\bat line\b|segfault", re.IGNORECASE
)
SOURCE_SHAPES = re.compile(r"\bdef\s|\blambda\b|\bimport\s|\)\s*:|->")
PATH_SHAPE = re.compile(r"[A-Za-z_]\.[A-Za-z0-9_]|[A-Za-z0-9_]\.[A-Za-z_]")
TOKENS = re.compile(r"[A-Za-z0-9_.-]+")


def digest(value):
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def normal(value):
    return " ".join(value.split()).casefold()


def screen_text(text, sources):
    """Raise ValueError unless text is bounded, plain, single-line prose of our own kind."""
    if type(text) is not str or not PROSE.fullmatch(text):
        raise ValueError("Finding text must be plain single-line prose")
    if (
        not MIN_FIELD_CHARS <= len(text) <= MAX_FIELD_BYTES
        or text != " ".join(text.split())
        or len(text.split()) < 4
    ):
        raise ValueError("Finding text length or shape is out of bounds")
    for pattern in (SECRET_WORDS, SECRET_SHAPES, PII_NUMBER, ERROR_TEXT, SOURCE_SHAPES):
        if pattern.search(text):
            raise ValueError("Finding text rejected by screening")
    for token in TOKENS.findall(text):
        token = token.strip(".-")
        if PATH_SHAPE.search(token) and token not in sources:
            raise ValueError("Finding text mentions an unapproved path")
    flat = normal(text)
    for content in sources.values():
        for line in content.splitlines():
            if len(line.strip()) >= 8 and normal(line).rstrip(".,;:") in flat:
                raise ValueError("Finding text copies source")
    return text


def validate_findings(value, sources):
    """Require a versioned, bounded report whose references match the selected snapshots.

    An empty findings list is a valid clean review: a model is never forced to invent a defect.
    It is a statement of what was reported, not proof that the selection is correct.
    """
    if (
        type(sources) is not dict
        or not sources
        or any(type(k) is not str or type(v) is not str for k, v in sources.items())
    ):
        raise ValueError("Invalid approved sources")
    if (
        type(value) is not dict
        or set(value) != {"report_version", "repository", "findings"}
        or type(value["report_version"]) is not int
        or value["report_version"] != REPORT_VERSION
        or value["repository"] != "tiny-shop"
        or type(value["findings"]) is not list
        or len(value["findings"]) > MAX_FINDINGS
    ):
        raise ValueError("Findings report identity/version invalid")
    identities, problems = set(), set()
    for finding in value["findings"]:
        if type(finding) is not dict or set(finding) != FIELDS:
            raise ValueError("Unknown finding fields")
        identity = finding["id"]
        if type(identity) is not str or not IDENTITY.fullmatch(identity) or identity in identities:
            raise ValueError("Invalid or duplicate finding identity")
        identities.add(identity)
        texts = [
            screen_text(finding[name], sources) for name in ("problem", "impact", "suggested_fix")
        ]
        if len({normal(t) for t in texts}) != 3 or normal(texts[0]) in problems:
            raise ValueError("Finding texts must be distinct")
        problems.add(normal(texts[0]))
        name, line = finding["file"], finding["line"]
        if type(name) is not str or name not in sources or type(line) is not int:
            raise ValueError("Finding references an unselected file")
        lines = sources[name].splitlines()
        if not 1 <= line <= len(lines) or not lines[line - 1].strip():
            raise ValueError("Finding references a nonexistent line")
        if finding["sha256"] != digest(sources[name]):
            raise ValueError("Finding hash differs from the selected snapshot")
    encoded = json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    if len(encoded.encode("utf-8")) > MAX_REPORT_BYTES:
        raise ValueError("Findings report too large")
    return value["findings"]


def escaped(text):
    return text.replace("*", "\\*").replace("_", "\\_")


def markdown_lines(value, sources):
    """Body lines for a validated report; prose is escaped and links are fixed local paths."""
    items = validate_findings(value, sources)
    if not items:
        return ["No findings reported. This is not proof that the selected files are correct.", ""]
    lines = []
    for item in items:
        reference = f"[{item['file']}:{item['line']}](files/{item['file']}#L{item['line']})"
        lines += [
            f"### {item['id']} — {reference}",
            "",
            f"- Problem: {escaped(item['problem'])}",
            f"- Impact: {escaped(item['impact'])}",
            f"- Suggested fix: {escaped(item['suggested_fix'])}",
            f"- Source hash: `{item['sha256']}`",
            "",
        ]
    return lines
