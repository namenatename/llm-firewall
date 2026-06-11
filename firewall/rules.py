# Ruleset to define prompt injection structures and patterns

from dataclasses import dataclass
from enum import Enum, IntEnum

# Rule Category for  threat categories
class RuleCategory(Enum):
    # Categories  for differentiated attacks and processes
    OBFUSCATION = "obfuscation"
    JAILBREAK = "jailbreak"
    CONTEXT_HIJACK = "context_hijack"
    PROMPT_LEAKAGE = "prompt_leakage"
    TOOL_ABUSE = "tool_abuse"

# Threat level weights with severity number assessment for risk scoring
class ThreatLevel(IntEnum):
    LOW = 10
    MEDIUM = 25
    HIGH = 50
    CRITICAL = 75

# Immutable container for individual detection rules
@dataclass(frozen=True)
class InjectionSignature:
    rule_id: str
    name: str
    category: RuleCategory
    pattern: str
    threat_level: ThreatLevel
    owasp_ref: str
    atlas_ref: str

# Active injection detection signatures predefined
SIGNATURE_REGISTRY: list[InjectionSignature] = [
    # Jailbreak Signatures
    InjectionSignature(
        rule_id="JB-001",
        name="Direct Prompt Injection",
        category=RuleCategory.JAILBREAK,
        pattern="you are now|from now on you|ignore previous",
        threat_level=ThreatLevel.HIGH,
        owasp_ref="LLM01",
        atlas_ref="AML.T0054"
    ),
    InjectionSignature(
        rule_id="JB-002",
        name="System Prompt Retrieval",
        category=RuleCategory.JAILBREAK,
        pattern="system:|reveal system",
        threat_level=ThreatLevel.HIGH,
        owasp_ref="LLM01",
        atlas_ref="AML.T0054"
    ),
    InjectionSignature(
        rule_id="JB-003",
        name="Persona Switch",
        category=RuleCategory.JAILBREAK,
        pattern="act as|pretend you are|as a security researcher",
        threat_level=ThreatLevel.HIGH,
        owasp_ref="LLM01",
        atlas_ref="AML.T0054"
    ),
    # Prompt Leakage Signatures
    InjectionSignature(
        rule_id="PL-001",
        name="Session Data Bleeding",
        category=RuleCategory.PROMPT_LEAKAGE,
        pattern="list all user details|list previous prompts",
        threat_level=ThreatLevel.MEDIUM,
        owasp_ref="LLM06",
        atlas_ref="AML.T0056"
    ),
    # Context Hijack Signatures
    InjectionSignature(
        rule_id="CH-001",
        name="Memory Context Poisoning",
        category=RuleCategory.CONTEXT_HIJACK,
        pattern="as stated previously|remember my preference for",
        threat_level=ThreatLevel.HIGH,
        owasp_ref="LLM01",
        atlas_ref="AML.T0080.000, AML.T0051.000"
    ),
    InjectionSignature(
        rule_id="CH-002",
        name="Thread Context Poisoning",
        category=RuleCategory.CONTEXT_HIJACK,
        pattern="the document says|as instructed above",
        threat_level=ThreatLevel.HIGH,
        owasp_ref="LLM01",
        atlas_ref="AML.T0080.001, AML.T0051.001"
    ),
    # Tool Abuse Signatures
    InjectionSignature(
        rule_id="TA-001",
        name="AI Agent Tool Invocation",
        category=RuleCategory.TOOL_ABUSE,
        pattern="run Python script|use your SQL tool|call the API|invoke function",
        threat_level=ThreatLevel.HIGH,
        owasp_ref="LLM03",
        atlas_ref="AML.T0053"
    ),
    # Obfuscation Signatures
    InjectionSignature(
        rule_id="OB-001",
        name="Base64 encoding",
        category=RuleCategory.OBFUSCATION,
        pattern="[A-Za-z0-9+/]{20,}={0,2}",
        threat_level=ThreatLevel.MEDIUM,
        owasp_ref="LLM01",
        atlas_ref="AML.T0054"
    ), 
    InjectionSignature(
        rule_id="OB-002",
        name="Encoding Retrieval",
        category=RuleCategory.OBFUSCATION,
        pattern="encode in base64|translate from base64|encode this",
        threat_level=ThreatLevel.HIGH,
        owasp_ref="LLM01",
        atlas_ref="AML.T0054"
    )
]








