import re
from typing import List, Dict, Any, Tuple
from backend.schemas import IndicatorItem

# Rule definitions with categories, regex patterns, severities, and weights
INDICATOR_RULES = [
    {
        "id": "urgency",
        "name": "Artificial Urgency & Time Pressure",
        "category": "Social Engineering",
        "severity": "HIGH",
        "score_impact": 20,
        "description": "Uses psychological pressure to force hasty decisions before the victim can verify authenticity.",
        "patterns": [
            r"\b(?:urgent|urgently|immediately|act now|last warning|final notice|within 24 hours?|within 12 hours?|expires? today|immediate action|hurry up|limited time)\b"
        ]
    },
    {
        "id": "threats",
        "name": "Coercive Threats & Intimidation",
        "category": "Extortion / Phishing",
        "severity": "CRITICAL",
        "score_impact": 28,
        "description": "Threatens negative consequences like account deactivation, police arrest, or legal penalties.",
        "patterns": [
            r"\b(?:account will be (?:blocked|suspended|terminated|deactivated|closed)|legal action|police complaint|arrest warrant|digital arrest|court notice|penalty|disconnected|fine will be charged)\b",
            r"\b(?:avoid permanent (?:blockage|deactivation)|power will be disconnected|electricity (?:power )?will be disconnected|prevent disconnection)\b"
        ]
    },
    {
        "id": "credentials",
        "name": "Sensitive Information & Credential Harvesting",
        "category": "Phishing / Account Takeover",
        "severity": "CRITICAL",
        "score_impact": 35,
        "description": "Requests highly confidential authentication tokens, passwords, PINs, or banking details.",
        "patterns": [
            r"\b(?:enter (?:your )?(?:otp|pin|cvv|password|passcode|netbanking password))\b",
            r"\b(?:send|provide|share) (?:the )?(?:otp|6-digit code|verification code|pin|password)\b",
            r"\b(?:update (?:your )?(?:pan|aadhaar|kyc|bank details|card details|debit card))\b"
        ]
    },
    {
        "id": "financial_demand",
        "name": "Advance Fee / Payment Demands",
        "category": "Financial Fraud",
        "severity": "HIGH",
        "score_impact": 25,
        "description": "Demands advance payment under the pretext of 'processing fees', 'tax', or 'security deposits'.",
        "patterns": [
            r"\b(?:processing fee|registration fee|dispatch fee|clearance fee|customs fee|rescheduling charge|redelivery fee|claim fee|security deposit)\b",
            r"\b(?:transfer|deposit|pay) (?:rs\.?|inr|\$|\u20b9)\s*\d+(?:,\d+)*(?:\s*(?:fee|charge|deposit|advance|immediately))?\b",
            r"\b(?:double your (?:money|bitcoin|crypto|investment)|guaranteed (?:returns?|\d+% return))\b"
        ]
    },
    {
        "id": "prize_lottery",
        "name": "Unsolicited Prize / Lottery Claims",
        "category": "Prize Scam",
        "severity": "HIGH",
        "score_impact": 22,
        "description": "Lures victims with fake lotteries, cash rewards, free iPhones, or massive unexpected payouts.",
        "patterns": [
            r"\b(?:congratulations!? you (?:have )?won|lucky (?:winner|draw|spin)|won rs\.?|won \$\d+|international lottery|mega jackpot|cash reward of rs|unclaimed cashback)\b",
            r"\b(?:claim your (?:free|prize|reward|gift voucher|cashback))\b"
        ]
    },
    {
        "id": "delivery_courier",
        "name": "Fake Delivery / Parcel Lure",
        "category": "Delivery Scam",
        "severity": "MEDIUM",
        "score_impact": 18,
        "description": "Impersonates couriers claiming a package is delayed, held at customs, or needs address updates.",
        "patterns": [
            r"\b(?:package|parcel|shipment|consignment) (?:is held|arrived|cannot be delivered|delayed|suspended|on hold)\b",
            r"\b(?:update (?:your )?delivery address|incomplete (?:delivery )?address|confirm street address|reschedule (?:your )?delivery)\b",
            r"\b(?:fedex|dhl|indiapost|blue\s*dart|ups courier)\b"
        ]
    },
    {
        "id": "fake_job",
        "name": "Work-From-Home / Task Scam Pattern",
        "category": "Job Scam",
        "severity": "HIGH",
        "score_impact": 20,
        "description": "Offers unrealistic pay for simple tasks like liking videos, rating hotels, or typing captchas.",
        "patterns": [
            r"\b(?:part-time job|work from home|earn rs\.?\s*\d+ (?:daily|per day)|liking (?:youtube )?videos|rating hotels|telegram task)\b",
            r"\b(?:no experience needed|daily payout via upi|contact (?:hr|manager) on telegram)\b"
        ]
    },
    {
        "id": "impersonation",
        "name": "Authority / Brand Impersonation",
        "category": "Impersonation",
        "severity": "HIGH",
        "score_impact": 18,
        "description": "Impersonates recognized institutions like banks, tax authorities, or popular tech companies.",
        "patterns": [
            r"\b(?:state bank of india|sbi|hdfc|icici|axis bank|income tax department|rbi safety|police department|cbi officer|telecom regulatory)\b",
            r"\b(?:amazon support|netflix membership|whatsapp support|appleid support|microsoft 365 security)\b"
        ]
    }
]

NEGATION_PREFIXES = ["do not ", "don't ", "never ", "should not ", "will not ", "cannot ", "will never "]

def is_negated(full_text: str, start_idx: int) -> bool:
    """Checks if a match is preceded by a safety negation (e.g. 'Do not share OTP')."""
    prefix = full_text[max(0, start_idx - 30):start_idx].lower()
    return any(neg in prefix for neg in NEGATION_PREFIXES)

def scan_rules(text: str) -> Tuple[List[IndicatorItem], int, Dict[str, int]]:
    """
    Scans input text against cybersecurity indicator patterns with contextual negation awareness.
    Returns:
      - List of IndicatorItem matches
      - Total rule score contribution
      - Category affinity counts
    """
    if not text:
        return [], 0, {}

    matched_indicators: List[IndicatorItem] = []
    total_score = 0
    category_affinities: Dict[str, int] = {}

    lower_text = text.lower()
    is_benign_transactional = any(w in lower_text for w in [
        "debited from", "credited to", "available balance", "valid for", "flight booking",
        "appointment with", "order from", "order with", "ride with driver", "attendance is mandatory"
    ]) and not any(w in lower_text for w in ["http://", "https://", "bit.ly", "urgent", "blocked", "suspended"])

    for rule in INDICATOR_RULES:
        # If message is clearly a benign transactional update and has no links or threats, don't flag brand name as impersonation
        if rule["id"] == "impersonation" and is_benign_transactional:
            continue

        found_evidences = []
        for pat in rule["patterns"]:
            for match in re.finditer(pat, text, re.IGNORECASE):
                # Check for negation if it's credentials or financial demand
                if rule["id"] in ["credentials", "threats", "financial_demand"]:
                    if is_negated(text, match.start()):
                        continue  # Legitimate advisory warning like "Do not share OTP"

                m_str = match.group(0)
                if m_str and m_str.lower() not in [e.lower() for e in found_evidences]:
                    found_evidences.append(m_str.strip())

        if found_evidences:
            matched_indicators.append(
                IndicatorItem(
                    name=rule["name"],
                    category=rule["category"],
                    severity=rule["severity"],
                    score_impact=rule["score_impact"],
                    description=rule["description"],
                    evidence=found_evidences[:5]  # limit to top 5 evidence snippets
                )
            )
            total_score += rule["score_impact"]
            category = rule["category"]
            category_affinities[category] = category_affinities.get(category, 0) + rule["score_impact"]

    # Deduplicate and cap rule score
    capped_score = min(total_score, 100)
    return matched_indicators, capped_score, category_affinities
