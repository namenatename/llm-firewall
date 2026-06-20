# Prompt validation for user inputs used to check for injection techniques
# First layer of security against prompt injection, works at ingest layer

import re
from dataclasses import dataclass, field
import signal
from enum import Enum
from firewall.rules import SIGNATURE_REGISTRY, InjectionSignature, ThreatLevel
from config import settings

# Static verdict for prompt validation and decision-making
class Verdict(Enum):
    BLOCKED = "BLOCKED"
    CLEAN = "CLEAN"

# Class structure for result processing with structure for each result
@dataclass
class FilterResult:
    verdict: Verdict
    risk_score: int = 0
    matched_rules: list[str] = field(default_factory=list)
    flagged_categories: list[str] = field(default_factory=list)
    input_preview: str = ""
    source: str = "user"

# Class structure for signature and regex pattern compiling
@dataclass
class CompiledRule:
    signature: InjectionSignature
    pattern: re.Pattern

# Multipliers based on prompt injection source
SOURCE_WEIGHTS: dict[str, float] = {
    "user": 1.0,
    "tool_response": 1.5,
    "product_data": 2.0,
    "external_agent": 2.0
}

# Function to build compiled patterns for injection signatures
def _build_compiled_registry() -> list[CompiledRule]:
    compiled_list: list[CompiledRule] = []
    for signature in SIGNATURE_REGISTRY:
        # Compile raw string from rules to create state machine
        pattern = re.compile(signature.pattern, re.IGNORECASE)
        compiled_list.append(CompiledRule(
            signature=signature,
            pattern=pattern)
        )
    return compiled_list

# Instantiation
COMPILED_REGISTRY = _build_compiled_registry()

# Handler for error codes
def _handler(signum, frame):
    raise TimeoutError

# Function to detect signature matches
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
    # Initialize the args hold results
    risk_score = 0
    matched_rules = []
    flagged_categories = []
    input_preview = text[:100]
    # Session timeout check
    if len(text) > settings.max_input_length:
        return FilterResult(
                verdict=Verdict.BLOCKED,
                risk_score=ThreatLevel.LOW,
                matched_rules=["INPUT_EXCEEDS_LIMIT"],
                flagged_categories=[],
                input_preview=input_preview,
                source=source)
    # Check cases of matches and regex timeout
    for rule in COMPILED_REGISTRY:
        match, timed_out = _safe_match(rule, text)
        # Timed out case should be taken into consideration
        # Regex will not normally timeout
        if timed_out:
                risk_score+=rule.signature.threat_level
                matched_rules.append("REDOS_SUSPECTED")
        # Case for matched sigs in text
        if match:
                risk_score+=rule.signature.threat_level
                matched_rules.append(rule.signature.rule_id)
                flagged_categories.append(rule.signature.category.value)
    flagged_categories=list(set(flagged_categories)) # deduplicate common categories
    # Build final score and verdict checking for passing/blocking message
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