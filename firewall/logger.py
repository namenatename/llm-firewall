import logging, json, uuid
from datetime import datetime, timezone
from pathlib import Path
from firewall.prompt_validation import FilterResult
from config import settings

logger = logging.getLogger("llm_firewall")
logger.setLevel(settings.log_level)
Path(settings.log_file_path).parent.mkdir(parents=True, exist_ok=True)
handler = logging.FileHandler(settings.log_file_path)
handler.setFormatter(logging.Formatter("%(message)s"))
logger.addHandler(handler)

def log_request(result: FilterResult) -> None:
    log_entry = {"timestamp": datetime.now(timezone.utc).isoformat(),
                 "request_id": str(uuid.uuid4()),
                 "verdict": result.verdict.value,
                 "risk_score": result.risk_score,
                 "matched_rules": result.matched_rules, 
                 "flagged_categories": result.flagged_categories,
                 "input_preview": result.input_preview, 
                 "source": result.source}
    logger.info(json.dumps(log_entry))


