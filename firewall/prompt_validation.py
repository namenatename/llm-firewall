# First layer of security against prompt injection, works at ingest layer

import re
from dataclasses import dataclass, field
import signal
from enum import Enum
from firewall.rules import SIGNATURE_REGISTRY, InjectionSignature, ThreatLevel
from config import settings

class Verdict(Enum):
    BLOCKED = "BLOCKED"
    CLEAN = "CLEAN"

@dataclass
class FilterResult:
    verdict: Verdict
    risk_score: int = 0
    matched_rules: list[str] = field(default_factory=list)
    flagged_categories: list[str] = field(default_factory=list)
    input_preview: str = ""
    source: str = "user"

@dataclass
class CompiledRule:
    signature: InjectionSignature
    pattern: re.Pattern

# Multipliers used to calculate severity and depth of attack surface
# E.g. external agent and product data could indicate an infrastructure attack vs. user-level input
SOURCE_WEIGHTS: dict[str, float] = {
    "user": 1.0,
    "tool_response": 1.5,
    "product_data": 2.0,
    "external_agent": 2.0
}

def _build_compiled_registry() -> list[CompiledRule]:
    compiled_list: list[CompiledRule] = []
    for signature in SIGNATURE_REGISTRY:
        pattern = re.compile(signature.pattern, re.IGNORECASE)
        compiled_list.append(CompiledRule(
            signature=signature,
            pattern=pattern)
        )
    return compiled_list

COMPILED_REGISTRY = _build_compiled_registry()

def _handler(signum, frame):
    raise TimeoutError

# Accounts for latency and timeout errors
def _safe_match(rule: CompiledRule, text: str) -> tuple[re.Match | None, bool]:
    signal.signal(signal.SIGALRM, _handler)
    signal.alarm(int(settings.regex_timeout_seconds))
    try:
        match = rule.pattern.search(text)
        return match, False
    except TimeoutError:
        return None, True
    finally:
        signal.alarm(0)

def scan_input(text: str, source="user") -> FilterResult:
    risk_score = 0
    matched_rules = []
    flagged_categories = []
    input_preview = text[:100]
    if len(text) > settings.max_input_length:
        return FilterResult(
                verdict=Verdict.BLOCKED,
                risk_score=ThreatLevel.LOW,
                matched_rules=["INPUT_EXCEEDS_LIMIT"],
                flagged_categories=[],
                input_preview=input_preview,
                source=source)
    for rule in COMPILED_REGISTRY:
        match, timed_out = _safe_match(rule, text)
        # Timed out case should be taken into consideration
        # Regex will not normally timeout
        if timed_out:
                risk_score+=rule.signature.threat_level
                matched_rules.append("REDOS_SUSPECTED")
        if match:
                risk_score+=rule.signature.threat_level
                matched_rules.append(rule.signature.rule_id)
                flagged_categories.append(rule.signature.category.value)
    flagged_categories=list(set(flagged_categories)) # deduplicate common categories, only one ref needed
    source_weight = SOURCE_WEIGHTS.get(source, 1.0)
    final_score = int(risk_score * source_weight)
    verdict = Verdict.BLOCKED if final_score >= settings.risk_score_threshold else Verdict.CLEAN
    return FilterResult(
                verdict=verdict,
                risk_score=final_score,
                matched_rules=matched_rules,
                flagged_categories=flagged_categories,
                input_preview=input_preview,
                source=source)