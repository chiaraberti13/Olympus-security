"""Detection testing harness: validate a rule against labeled synthetic events.

Mirrors how real detection-engineering teams keep rules honest: each rule
ships with a small set of events labeled "should fire" / "should not
fire", and the harness reports any mismatch instead of trusting the rule
blindly — the same testing discipline applied to detection content
instead of application code.
"""

from __future__ import annotations

from dataclasses import dataclass

from olympus.apollo.engine import matches
from olympus.apollo.rules import DetectionRule
from olympus.core.models import Event


@dataclass(frozen=True)
class LabeledEvent:
    """A synthetic event plus the expected verdict for a rule under test."""

    event: Event
    should_match: bool
    label: str = ""


@dataclass(frozen=True)
class TestCaseResult:
    """The outcome of evaluating one :class:`LabeledEvent` against a rule."""

    label: str
    expected: bool
    actual: bool

    @property
    def passed(self) -> bool:
        """Return ``True`` if the rule's verdict matched the expected one."""
        return self.expected == self.actual


@dataclass(frozen=True)
class RuleTestReport:
    """The aggregate result of running a rule's full labeled test suite."""

    rule_id: str
    results: list[TestCaseResult]

    @property
    def passed(self) -> bool:
        """Return ``True`` if every test case passed."""
        return all(result.passed for result in self.results)

    @property
    def failures(self) -> list[TestCaseResult]:
        """Return only the failing test cases."""
        return [result for result in self.results if not result.passed]


def run_rule_tests(rule: DetectionRule, cases: list[LabeledEvent]) -> RuleTestReport:
    """Evaluate ``rule`` against every labeled case and report pass/fail per case."""
    results = [
        TestCaseResult(
            label=case.label or case.event.event_id,
            expected=case.should_match,
            actual=matches(rule, case.event),
        )
        for case in cases
    ]
    return RuleTestReport(rule_id=rule.rule_id, results=results)
