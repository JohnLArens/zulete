import imaplib, ssl, email
from email.header import decode_header, make_header
from .filtering import normalize_sender, score_message
from .crypto import decrypt_text

def decode_text(v):
    try: return str(make_header(decode_header(v or "")))
    except Exception: return v or ""

def extract_body(msg, limit=6000):
    chunks=[]
    if msg.is_multipart():
        for part in msg.walk():
            if part.get_content_type()=="text/plain" and "attachment" not in str(part.get("Content-Disposition","")).lower():
                try:
                    chunks.append(part.get_payload(decode=True).decode(part.get_content_charset() or "utf-8","replace"))
                except Exception:
                    pass
    else:
        try:
            chunks.append(msg.get_payload(decode=True).decode(msg.get_content_charset() or "utf-8","replace"))
        except Exception:
            pass
    return "\n".join(chunks)[:limit]

def safe_create(M,name):
    try: M.create(name)
    except Exception: pass

def move(M,uid,destination):
    safe_create(M,destination)
    typ,_=M.uid("COPY",uid,destination)
    if typ=="OK":
        M.uid("STORE",uid,"+FLAGS","(\\Deleted)")
        M.expunge()
        return True
    return False

def trash(M,uid,permanent=False):
    if permanent:
        M.uid("STORE",uid,"+FLAGS","(\\Deleted)")
        M.expunge(); return "permanently deleted"
    for box in ["Trash","Deleted Messages"]:
        try:
            if move(M,uid,box): return "moved to Trash"
        except Exception: pass
    M.uid("STORE",uid,"+FLAGS","(\\Deleted)")
    return "marked deleted"

def scan_icloud(user, enc_password, rule_lookup, settings, activity_cb, quarantine_cb, max_messages=75):
    password=decrypt_text(enc_password)
    M=imaplib.IMAP4_SSL("imap.mail.me.com",993,ssl_context=ssl.create_default_context())
    M.login(user,password)
    M.select("INBOX")
    _,data=M.uid("search",None,"ALL")
    uids=(data[0] or b"").split()[-max_messages:]
    actions={"allowed":0,"review":0,"spam":0,"deleted":0}

    for uid in reversed(uids):
        typ,msgdata=M.uid("fetch",uid,"(RFC822)")
        if typ!="OK" or not msgdata or not isinstance(msgdata[0],tuple): continue
        msg=email.message_from_bytes(msgdata[0][1])
        sender=normalize_sender(msg.get("From",""))
        subject=decode_text(msg.get("Subject",""))
        body=extract_body(msg)
        score,reasons,status,kind=score_message(sender,subject,body,msg,rule_lookup)

        auto_delete=status=="blocked" and (
            (kind=="email" and settings["auto_delete_blocked_senders"]) or
            (kind=="domain" and settings["auto_delete_blocked_domains"])
        )
        if auto_delete:
            detail=trash(M,uid,settings["permanent_delete"])
            actions["deleted"]+=1
            activity_cb("icloud",sender,subject,"deleted",f"Known blocked {kind}; {detail}")
        elif score>=settings["spam_threshold"]:
            move(M,uid,"Zulete Spam")
            actions["spam"]+=1
            activity_cb("icloud",sender,subject,"spam",", ".join(reasons[:5]))
        elif score>=settings["review_threshold"]:
            move(M,uid,"Zulete Review")
            quarantine_cb("icloud",sender,subject,score,", ".join(reasons[:5]))
            actions["review"]+=1
            activity_cb("icloud",sender,subject,"review",", ".join(reasons[:5]))
        else:
            actions["allowed"]+=1
    try: M.close()
    except Exception: pass
    M.logout()
    return actions
