"""Payload-blind telemetry and alert contracts used throughout the prototype."""
from __future__ import annotations
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from typing import Any
import uuid

THREATS = {"ddos", "c2_beaconing", "dga_dns_tunnel", "encrypted_malware", "recon_scan", "exfiltration"}

def now() -> str:
    return datetime.now(timezone.utc).isoformat()

def flow(event: dict[str, Any]) -> dict[str, Any]:
    return {k: event.get(k, "" if k in {"src_ip", "dst_ip", "proto"} else 0)
            for k in ("src_ip", "src_port", "dst_ip", "dst_port", "proto")}

def alert(event: dict[str, Any], threat_class: str, subtype: str, score: float,
          evidence: dict[str, Any], mitre: list[str], model_version: str) -> dict[str, Any]:
    # score is a normalized detector score, not a calibrated probability.
    score = round(max(0.0, min(1.0, score)), 3)
    severity = "critical" if score >= .9 else "high" if score >= .7 else "medium" if score >= .45 else "low"
    record={"alert_id": str(uuid.uuid4()), "timestamp": event.get("event_ts", now()),
            "flow_id": flow(event), "threat_class": threat_class, "subtype": subtype,
            "confidence": score, "severity": severity, "supporting_evidence": evidence,
            "mitre_attack": mitre, "model_version": model_version}
    from engine.validation import validate_alert
    return validate_alert(record)
