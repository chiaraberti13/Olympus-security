from pathlib import Path
import re


TEMPLATES_DIR = Path(__file__).resolve().parents[1] / "templates"
INLINE_EVENT_HANDLER_PATTERN = re.compile(r"\son[a-z]+\s*=", re.IGNORECASE)
INLINE_STYLE_ATTR_PATTERN = re.compile(r"\sstyle\s*=", re.IGNORECASE)
SCRIPT_TAG_PATTERN = re.compile(
    r"<script(?P<attrs>[^>]*)>(?P<body>.*?)</script>",
    re.IGNORECASE | re.DOTALL,
)


def _iter_template_files():
    for template_file in sorted(TEMPLATES_DIR.glob("*.html")):
        yield template_file, template_file.read_text(encoding="utf-8")


def test_templates_do_not_use_inline_style_attributes_or_event_handlers():
    violations = []

    for template_file, content in _iter_template_files():
        if INLINE_STYLE_ATTR_PATTERN.search(content):
            violations.append(f"{template_file.name}: contiene attributi style inline")
        if INLINE_EVENT_HANDLER_PATTERN.search(content):
            violations.append(
                f"{template_file.name}: contiene event handler inline (on*)"
            )

    assert not violations, "\n".join(violations)


def test_templates_disallow_executable_inline_script_blocks():
    violations = []

    for template_file, content in _iter_template_files():
        for match in SCRIPT_TAG_PATTERN.finditer(content):
            attrs = match.group("attrs") or ""
            body = (match.group("body") or "").strip()

            # Consentiamo script inline solo per payload JSON non eseguibili.
            if 'type="application/json"' in attrs.lower():
                continue

            if body:
                violations.append(
                    f"{template_file.name}: blocco <script> inline eseguibile rilevato"
                )

    assert not violations, "\n".join(violations)
