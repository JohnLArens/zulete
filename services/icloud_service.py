import imaplib, ssl, email, time
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


def process_uid(M, uid, rule_lookup, settings, activity_cb, quarantine_cb):
    typ,msgdata=M.uid("fetch",uid,"(RFC822)")
    if typ!="OK" or not msgdata or not isinstance(msgdata[0],tuple):
        return None
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
        activity_cb("icloud",sender,subject,"deleted",f"Known blocked {kind}; {detail}")
        return "deleted"
    if score>=settings["spam_threshold"]:
        move(M,uid,"Zulete Spam")
        activity_cb("icloud",sender,subject,"spam",", ".join(reasons[:5]))
        return "spam"
    if score>=settings["review_threshold"]:
        move(M,uid,"Zulete Review")
        quarantine_cb("icloud",sender,subject,score,", ".join(reasons[:5]))
        activity_cb("icloud",sender,subject,"review",", ".join(reasons[:5]))
        return "review"
    return "allowed"


def scan_icloud(user, enc_password, rule_lookup, settings, activity_cb, quarantine_cb, max_messages=75):
    password=decrypt_text(enc_password)
    M=imaplib.IMAP4_SSL("imap.mail.me.com",993,ssl_context=ssl.create_default_context())
    M.login(user,password)
    M.select("INBOX")
    _,data=M.uid("search",None,"ALL")
    uids=(data[0] or b"").split()[-max_messages:]
    actions={"allowed":0,"review":0,"spam":0,"deleted":0}
    for uid in reversed(uids):
        action=process_uid(M,uid,rule_lookup,settings,activity_cb,quarantine_cb)
        if action in actions: actions[action]+=1
    try: M.close()
    except Exception: pass
    M.logout()
    return actions


def watch_icloud(user, enc_password, rule_lookup, settings_provider, activity_cb, quarantine_cb, stop_event, poll_seconds=10):
    """Near-real-time iCloud watcher.

    Apple receives the message first; this worker detects new INBOX UIDs and processes
    them within the configured polling interval. It reconnects automatically after
    network/server errors and never permanently deletes classifier-only spam.
    """
    password=decrypt_text(enc_password)
    seen=set()
    while not stop_event.is_set():
        M=None
        try:
            M=imaplib.IMAP4_SSL("imap.mail.me.com",993,ssl_context=ssl.create_default_context())
            M.login(user,password)
            M.select("INBOX")
            _,data=M.uid("search",None,"ALL")
            current=(data[0] or b"").split()
            seen=set(current)
            while not stop_event.wait(poll_seconds):
                M.noop()
                _,data=M.uid("search",None,"ALL")
                current=(data[0] or b"").split()
                new_uids=[uid for uid in current if uid not in seen]
                if new_uids:
                    settings=settings_provider()
                    for uid in new_uids:
                        process_uid(M,uid,rule_lookup,settings,activity_cb,quarantine_cb)
                    seen.update(new_uids)
        except Exception as exc:
            activity_cb("icloud","","","watcher",f"Live Protection reconnecting: {type(exc).__name__}")
            stop_event.wait(15)
        finally:
            if M:
                try: M.logout()
                except Exception: pass
