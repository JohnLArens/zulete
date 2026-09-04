import base64, json
from email import message_from_bytes
from email.header import decode_header, make_header
from google.oauth2.credentials import Credentials
from googleapiclient.discovery import build
from .filtering import normalize_sender, score_message
from .crypto import decrypt_text

GMAIL_SCOPES = ["https://www.googleapis.com/auth/gmail.modify"]

def decode_header_text(v):
    try:
        return str(make_header(decode_header(v or "")))
    except Exception:
        return v or ""

def extract_text(msg, limit=6000):
    chunks=[]
    if msg.is_multipart():
        for p in msg.walk():
            if p.get_content_type()=="text/plain" and "attachment" not in str(p.get("Content-Disposition","")).lower():
                try:
                    chunks.append(p.get_payload(decode=True).decode(p.get_content_charset() or "utf-8","replace"))
                except Exception:
                    pass
    else:
        try:
            chunks.append(msg.get_payload(decode=True).decode(msg.get_content_charset() or "utf-8","replace"))
        except Exception:
            pass
    return "\n".join(chunks)[:limit]

def service_from_token(enc_token):
    info=json.loads(decrypt_text(enc_token))
    creds=Credentials.from_authorized_user_info(info, GMAIL_SCOPES)
    return build("gmail","v1",credentials=creds,cache_discovery=False)

def ensure_label(service, name):
    labels=service.users().labels().list(userId="me").execute().get("labels",[])
    for l in labels:
        if l["name"]==name:
            return l["id"]
    created=service.users().labels().create(userId="me",body={
        "name":name,"labelListVisibility":"labelShow","messageListVisibility":"show"
    }).execute()
    return created["id"]

def scan_gmail(enc_token, rule_lookup, settings, activity_cb, quarantine_cb, max_messages=75):
    svc=service_from_token(enc_token)
    review_id=ensure_label(svc,"Zulete Review")
    spam_id=ensure_label(svc,"Zulete Spam")
    actions={"allowed":0,"review":0,"spam":0,"deleted":0}
    resp=svc.users().messages().list(userId="me",labelIds=["INBOX"],maxResults=max_messages).execute()
    for item in resp.get("messages",[]):
        mid=item["id"]
        raw=svc.users().messages().get(userId="me",id=mid,format="raw").execute()
        data=base64.urlsafe_b64decode(raw["raw"] + "===")
        msg=message_from_bytes(data)
        sender=normalize_sender(msg.get("From",""))
        subject=decode_header_text(msg.get("Subject",""))
        body=extract_text(msg)
        score,reasons,status,kind=score_message(sender,subject,body,msg,rule_lookup)

        auto_delete = status=="blocked" and (
            (kind=="email" and settings["auto_delete_blocked_senders"]) or
            (kind=="domain" and settings["auto_delete_blocked_domains"])
        )
        if auto_delete:
            if settings["permanent_delete"]:
                svc.users().messages().delete(userId="me",id=mid).execute()
                detail="permanently deleted"
            else:
                svc.users().messages().trash(userId="me",id=mid).execute()
                detail="moved to Trash"
            actions["deleted"]+=1
            activity_cb("gmail",sender,subject,"deleted",f"Known blocked {kind}; {detail}")
        elif score>=settings["spam_threshold"]:
            svc.users().messages().modify(userId="me",id=mid,body={
                "addLabelIds":[spam_id],"removeLabelIds":["INBOX"]
            }).execute()
            actions["spam"]+=1
            activity_cb("gmail",sender,subject,"spam",", ".join(reasons[:5]))
        elif score>=settings["review_threshold"]:
            svc.users().messages().modify(userId="me",id=mid,body={
                "addLabelIds":[review_id],"removeLabelIds":["INBOX"]
            }).execute()
            quarantine_cb("gmail",sender,subject,score,", ".join(reasons[:5]))
            actions["review"]+=1
            activity_cb("gmail",sender,subject,"review",", ".join(reasons[:5]))
        else:
            actions["allowed"]+=1
    return actions
