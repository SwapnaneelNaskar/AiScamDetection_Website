from typing import List, Dict, Any, Optional, Tuple
from backend.schemas import IndicatorItem, URLAnalysisResult, AnalyzeResponse
from backend.classifier import predict_scam
from backend.rule_engine import scan_rules
from backend.url_analyzer import analyze_url, extract_urls

def calculate_risk(
    text: str,
    raw_url: str = "",
    input_type: str = "message"
) -> Dict[str, Any]:
    """
    Fuses Machine Learning probabilities, NLP heuristic indicators,
    and URL technical features into an explainable risk assessment.
    """
    cleaned_text = (text or "").strip()
    cleaned_url = (raw_url or "").strip()

    # 1. URL Resolution
    # If a direct URL was provided in URL mode, analyze it
    # If text contains embedded URLs, extract and analyze the primary one
    target_url = cleaned_url
    if not target_url and cleaned_text:
        embedded_urls = extract_urls(cleaned_text)
        if embedded_urls:
            target_url = embedded_urls[0]

    url_result: Optional[URLAnalysisResult] = None
    url_score = 0
    if target_url:
        url_result = analyze_url(target_url)
        url_score = url_result.url_risk_score

    # 2. Rule-Based Indicator Scanning
    indicators, rule_score, category_affinities = scan_rules(cleaned_text)

    # If standalone URL was analyzed, add URL-specific indicators
    if url_result and url_result.flags:
        indicators.append(
            IndicatorItem(
                name="Suspicious URL Characteristics",
                category="Technical Anomaly",
                severity="HIGH" if url_score > 50 else "MEDIUM",
                score_impact=min(url_score, 40),
                description=f"Technical inspection flagged {len(url_result.flags)} issue(s) with the embedded/provided link.",
                evidence=url_result.flags[:4]
            )
        )

    # 3. Machine Learning Classification
    # If only a URL was submitted, construct synthetic text for ML classifier
    ml_eval_text = cleaned_text
    if not ml_eval_text and target_url:
        ml_eval_text = f"Check this website link: {target_url}"

    ml_res = predict_scam(ml_eval_text)
    ml_scam_prob = ml_res["probability"]
    ml_score = int(ml_scam_prob * 100)

    # 4. Multi-Signal Fusion Formula
    # Weights: ML = 40%, Rules = 35%, URL = 25% (if URL present)
    # If no URL present: ML = 55%, Rules = 45%
    if target_url:
        composite_score = (ml_score * 0.40) + (rule_score * 0.35) + (url_score * 0.25)
    else:
        composite_score = (ml_score * 0.55) + (rule_score * 0.45)

    risk_score = int(round(composite_score))

    # Critical Escalation Rules (Cybersecurity overrides)
    indicator_names = [ind.name.lower() for ind in indicators]
    has_credentials = any("credential" in n for n in indicator_names)
    has_urgency = any("urgency" in n for n in indicator_names)
    has_threats = any("threat" in n for n in indicator_names)
    has_fees = any("fee" in n or "demand" in n for n in indicator_names)
    has_prize = any("prize" in n or "lottery" in n for n in indicator_names)
    has_job = any("job" in n or "task" in n for n in indicator_names)
    has_delivery = any("delivery" in n or "parcel" in n for n in indicator_names)

    # Severe credential harvesting or phishing escalation
    if has_credentials and (has_urgency or has_threats or (url_result and url_score > 30)):
        risk_score = max(risk_score, 90)
    elif has_credentials:
        risk_score = max(risk_score, 82)

    # Advance fee + prize scam escalation
    if has_prize and (has_fees or has_urgency or target_url):
        risk_score = max(risk_score, 88)
    elif has_prize:
        risk_score = max(risk_score, 82)

    # Job / Task Scam escalation
    if has_job:
        risk_score = max(risk_score, 86)

    # Coercive threat / utility cutoff escalation
    if has_threats and (has_urgency or has_fees or "power" in cleaned_text.lower() or "bill" in cleaned_text.lower()):
        risk_score = max(risk_score, 86)
    elif has_threats:
        risk_score = max(risk_score, 80)

    # Delivery scam with fees
    if has_delivery and (has_fees or target_url):
        risk_score = max(risk_score, 85)

    # Brand spoofing or IP in URL escalation
    if url_result and (url_result.is_ip_address or any("spoof" in f.lower() for f in url_result.flags)):
        risk_score = max(risk_score, 85)

    # If purely legitimate bank alert with no external link and no threat
    if ml_scam_prob < 0.15 and rule_score == 0 and url_score == 0:
        risk_score = min(risk_score, 15)

    risk_score = min(max(risk_score, 0), 100)

    # 5. Risk Level Assignment
    if risk_score >= 85:
        risk_level = "CRITICAL"
    elif risk_score >= 65:
        risk_level = "HIGH"
    elif risk_score >= 35:
        risk_level = "MEDIUM"
    else:
        risk_level = "LOW"

    is_scam = risk_score >= 50

    # 6. Primary Category Resolution
    if not is_scam:
        primary_category = "Legitimate"
    else:
        if has_prize:
            primary_category = "Prize Scam"
        elif any("delivery" in n for n in indicator_names):
            primary_category = "Delivery Scam"
        elif any("job" in n for n in indicator_names):
            primary_category = "Job Scam"
        elif has_threats and not has_credentials:
            primary_category = "Financial Scam"
        elif has_credentials or (url_result and url_score > 30):
            primary_category = "Phishing"
        elif any("impersonation" in n for n in indicator_names):
            primary_category = "Impersonation"
        elif ml_res["predicted_category"] != "Legitimate":
            primary_category = ml_res["predicted_category"]
        else:
            primary_category = "Phishing / Social Engineering"

    # 7. Actionable Safety Recommendations
    recommendations = []
    if risk_level in ["HIGH", "CRITICAL"]:
        if has_credentials:
            recommendations.append("NEVER disclose your OTP, PIN, password, or card CVV. Legitimate banks and service providers never ask for credentials via messages.")
        if target_url:
            recommendations.append("Do NOT click on the link. If you need to access this service, type the verified official web address directly into your browser.")
        if has_threats:
            recommendations.append("Ignore intimidation tactics regarding immediate police arrest or account deactivation. Contact the institution via verified public helpline numbers.")
        if has_prize or has_fees:
            recommendations.append("Do NOT send advance processing fees, registration charges, or crypto transfers. Real prizes do not require claim fees.")
        if any("job" in n for n in indicator_names):
            recommendations.append("Avoid Telegram or WhatsApp recruitment tasks promising high daily payouts for rating products or liking videos.")
        recommendations.append("Block the sender and report the message on the National Cyber Crime Reporting Portal (cybercrime.gov.in / 1930).")
    elif risk_level == "MEDIUM":
        recommendations.append("Exercise caution. Verify the sender's identity through official channels before responding or clicking any links.")
        recommendations.append("Check the sender ID or email domain carefully for subtle misspellings.")
    else:
        recommendations.append("No immediate scam indicators were detected.")
        recommendations.append("Always follow cyber hygiene: never share authentication codes or transfer money without independent verification.")

    # 8. Summary Explanation
    if is_scam:
        summary = (
            f"Flagged as {risk_level} RISK (Score: {risk_score}/100) under category '{primary_category}'. "
            f"The system detected {len(indicators)} warning sign(s) including "
            f"{', '.join([ind.name for ind in indicators[:3]])} with an AI scam probability of {int(ml_scam_prob * 100)}%."
        )
    else:
        summary = (
            f"Assessed as {risk_level} RISK (Score: {risk_score}/100). The message exhibits standard characteristics "
            f"of legitimate communication without coercive pressure, credential theft attempts, or deceptive domain links."
        )

    viva_summary = (
        f"Multi-Signal Architecture Result: Combined ML confidence ({int(ml_scam_prob * 100)}%), "
        f"Rule-Based Heuristic Severity ({rule_score} pts), and Technical URL Analysis ({url_score} pts) "
        f"to compute an explainable risk metric of {risk_score}/100."
    )

    return {
        "risk_score": risk_score,
        "risk_level": risk_level,
        "primary_category": primary_category,
        "is_scam": is_scam,
        "ml_scam_probability": ml_scam_prob,
        "ml_confidence_label": ml_res["confidence_label"],
        "detected_indicators": indicators,
        "url_analysis": url_result,
        "safety_recommendations": recommendations,
        "summary_explanation": summary,
        "viva_summary": viva_summary
    }
