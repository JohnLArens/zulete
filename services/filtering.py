import re
from email.utils import parseaddr

SPAM_PHRASES = [
    "urgent action required","verify your account","winner","you have won",
    "claim your prize","gift card","crypto investment","limited time offer",
    "act now","risk free","guaranteed income","click here immediately",
    "payment failed","account suspended","unusual activity","final notice",
    "dear customer","wire transfer","bitcoin","free money","invoice overdue",
    "confirm your identity","your mailbox is full","password expires today"
]
SUSPICIOUS_TLDS = {".xyz",".top",".click",".loan",".work",".zip",".mov",".gq",".tk"}

def normalize_sender(raw):
    return parseaddr(raw or "")[1].strip().lower()

def domain_of(addr):
    return addr.split("@",1)[1].lower() if "@" in addr else ""

def score_message(sender, subject, body, headers, rule_lookup):
    text=(subject+" "+body).lower()
    score=0
    reasons=[]
    status,kind=rule_lookup(sender)

    if status=="allowed":
        return 0, ["trusted sender"], status, kind
    if status=="blocked":
        return 100, [f"blocked {kind}"], status, kind

    for p in SPAM_PHRASES:
        if p in text:
            score += 8
            reasons.append(f'phrase: {p}')
    links=text.count("http://")+text.count("https://")
    if links >= 4:
        score += min(24, 8 + links*2)
        reasons.append("many links")
    if subject.count("!") >= 3:
        score += 8; reasons.append("excessive punctuation")
    if re.search(r"\b[A-Z]{8,}\b", subject):
        score += 8; reasons.append("all-caps wording")

    dom=domain_of(sender)
    if any(dom.endswith(t) for t in SUSPICIOUS_TLDS):
        score += 18; reasons.append("suspicious sending domain")

    auth=(headers.get("Authentication-Results","") or "").lower()
    if "spf=fail" in auth:
        score += 18; reasons.append("SPF failed")
    if "dkim=fail" in auth:
        score += 18; reasons.append("DKIM failed")
    if "dmarc=fail" in auth:
        score += 22; reasons.append("DMARC failed")

    reply=normalize_sender(headers.get("Reply-To",""))
    if reply and domain_of(reply) and domain_of(reply)!=dom:
        score += 10; reasons.append("Reply-To differs from sender domain")

    return min(score,100), reasons or ["no strong spam signals"], None, None
