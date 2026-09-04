from flask import Flask, render_template, request, redirect, url_for, flash, session
from pathlib import Path
from datetime import datetime
import sqlite3, os, json
from apscheduler.schedulers.background import BackgroundScheduler
from google_auth_oauthlib.flow import Flow
from services.crypto import encrypt_text
from services.gmail_service import scan_gmail, GMAIL_SCOPES
from services.icloud_service import scan_icloud
from services.filtering import domain_of

APP_DIR=Path(__file__).parent
DB_PATH=APP_DIR/"zulete.db"

app=Flask(__name__)
app.secret_key=os.environ.get("ZULETE_SECRET","change-this-before-public-deployment")

def db():
    c=sqlite3.connect(DB_PATH)
    c.row_factory=sqlite3.Row
    return c

def init_db():
    c=db()
    c.executescript("""
    CREATE TABLE IF NOT EXISTS settings(key TEXT PRIMARY KEY,value TEXT NOT NULL);
    CREATE TABLE IF NOT EXISTS accounts(
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      provider TEXT UNIQUE NOT NULL,
      address TEXT,
      encrypted_secret TEXT,
      connected INTEGER NOT NULL DEFAULT 0,
      updated_at TEXT
    );
    CREATE TABLE IF NOT EXISTS senders(
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      value TEXT NOT NULL,
      kind TEXT NOT NULL,
      status TEXT NOT NULL,
      created_at TEXT NOT NULL,
      UNIQUE(value,kind)
    );
    CREATE TABLE IF NOT EXISTS quarantine(
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      account TEXT,sender TEXT,subject TEXT,score INTEGER,reason TEXT,
      status TEXT DEFAULT 'review',created_at TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS activity(
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      account TEXT,sender TEXT,subject TEXT,action TEXT,detail TEXT,created_at TEXT NOT NULL
    );
    """)
    defaults={
      "auto_delete_blocked_senders":"1","auto_delete_blocked_domains":"0",
      "permanent_delete":"0","spam_threshold":"70","review_threshold":"40",
      "auto_scan":"1"
    }
    for k,v in defaults.items():
        c.execute("INSERT OR IGNORE INTO settings(key,value) VALUES (?,?)",(k,v))
    for p in ("gmail","icloud"):
        c.execute("INSERT OR IGNORE INTO accounts(provider,connected) VALUES(?,0)",(p,))
    c.commit(); c.close()

def get_setting(k,default=""):
    c=db(); r=c.execute("SELECT value FROM settings WHERE key=?",(k,)).fetchone(); c.close()
    return r["value"] if r else default

def set_setting(k,v):
    c=db(); c.execute("INSERT INTO settings(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",(k,str(v))); c.commit(); c.close()

def settings_dict():
    return {
      "auto_delete_blocked_senders":get_setting("auto_delete_blocked_senders","1")=="1",
      "auto_delete_blocked_domains":get_setting("auto_delete_blocked_domains","0")=="1",
      "permanent_delete":get_setting("permanent_delete","0")=="1",
      "spam_threshold":int(get_setting("spam_threshold","70")),
      "review_threshold":int(get_setting("review_threshold","40")),
      "auto_scan":get_setting("auto_scan","1")=="1"
    }

def account(provider):
    c=db(); r=c.execute("SELECT * FROM accounts WHERE provider=?",(provider,)).fetchone(); c.close(); return r

def rule_lookup(sender):
    dom=domain_of(sender)
    c=db()
    r=c.execute("SELECT status,kind FROM senders WHERE kind='email' AND value=?",(sender,)).fetchone()
    if not r and dom:
        r=c.execute("SELECT status,kind FROM senders WHERE kind='domain' AND value=?",(dom,)).fetchone()
    c.close()
    return (r["status"],r["kind"]) if r else (None,None)

def activity_cb(acct,sender,subject,action,detail):
    c=db(); c.execute("INSERT INTO activity(account,sender,subject,action,detail,created_at) VALUES(?,?,?,?,?,?)",
      (acct,sender,subject,action,detail,datetime.now().isoformat(timespec="seconds"))); c.commit(); c.close()

def quarantine_cb(acct,sender,subject,score,reason):
    c=db(); c.execute("INSERT INTO quarantine(account,sender,subject,score,reason,created_at) VALUES(?,?,?,?,?,?)",
      (acct,sender,subject,score,reason,datetime.now().isoformat(timespec="seconds"))); c.commit(); c.close()

def run_scan(provider, silent=False):
    s=settings_dict()
    try:
        a=account(provider)
        if not a or not a["connected"]:
            raise RuntimeError(f"{provider.title()} is not connected.")
        if provider=="gmail":
            actions=scan_gmail(a["encrypted_secret"],rule_lookup,s,activity_cb,quarantine_cb)
        else:
            actions=scan_icloud(a["address"],a["encrypted_secret"],rule_lookup,s,activity_cb,quarantine_cb)
        if not silent: flash(f"{provider.title()} scan complete: {actions}")
    except Exception as e:
        if not silent: flash(f"{provider.title()} scan failed: {e}")

def scheduled_scan():
    if not settings_dict()["auto_scan"]: return
    for p in ("gmail","icloud"):
        a=account(p)
        if a and a["connected"]:
            run_scan(p,silent=True)

@app.route("/")
def index():
    c=db()
    activity=c.execute("SELECT * FROM activity ORDER BY id DESC LIMIT 14").fetchall()
    metrics={
      "deleted":c.execute("SELECT COUNT(*) c FROM activity WHERE action='deleted'").fetchone()["c"],
      "review":c.execute("SELECT COUNT(*) c FROM quarantine WHERE status='review'").fetchone()["c"],
      "blocked":c.execute("SELECT COUNT(*) c FROM senders WHERE status='blocked'").fetchone()["c"],
      "trusted":c.execute("SELECT COUNT(*) c FROM senders WHERE status='allowed'").fetchone()["c"]
    }
    accts={r["provider"]:r for r in c.execute("SELECT * FROM accounts").fetchall()}
    c.close()
    return render_template("index.html",activity=activity,metrics=metrics,accounts=accts,settings=settings_dict())

@app.post("/scan/<provider>")
def scan(provider):
    if provider in ("gmail","icloud"): run_scan(provider)
    return redirect(url_for("index"))

@app.route("/connect")
def connect():
    return render_template("connect.html",gmail=account("gmail"),icloud=account("icloud"),
      google_ready=bool(os.environ.get("GOOGLE_CLIENT_ID") and os.environ.get("GOOGLE_CLIENT_SECRET")),
      master_ready=bool(os.environ.get("ZULETE_MASTER_KEY")))

@app.get("/connect/gmail")
def connect_gmail():
    cid=os.environ.get("GOOGLE_CLIENT_ID")
    secret=os.environ.get("GOOGLE_CLIENT_SECRET")
    redirect_uri=os.environ.get("GOOGLE_REDIRECT_URI","http://127.0.0.1:5055/oauth2callback")
    if not cid or not secret:
        flash("Google OAuth credentials are not configured.")
        return redirect(url_for("connect"))
    config={"web":{"client_id":cid,"client_secret":secret,
      "auth_uri":"https://accounts.google.com/o/oauth2/auth",
      "token_uri":"https://oauth2.googleapis.com/token","redirect_uris":[redirect_uri]}}
    flow=Flow.from_client_config(config,scopes=GMAIL_SCOPES,redirect_uri=redirect_uri)
    auth_url,state=flow.authorization_url(access_type="offline",include_granted_scopes="true",prompt="consent")
    session["oauth_state"]=state
    return redirect(auth_url)

@app.get("/oauth2callback")
def oauth2callback():
    cid=os.environ.get("GOOGLE_CLIENT_ID"); secret=os.environ.get("GOOGLE_CLIENT_SECRET")
    redirect_uri=os.environ.get("GOOGLE_REDIRECT_URI","http://127.0.0.1:5055/oauth2callback")
    config={"web":{"client_id":cid,"client_secret":secret,
      "auth_uri":"https://accounts.google.com/o/oauth2/auth",
      "token_uri":"https://oauth2.googleapis.com/token","redirect_uris":[redirect_uri]}}
    flow=Flow.from_client_config(config,scopes=GMAIL_SCOPES,state=session.get("oauth_state"),redirect_uri=redirect_uri)
    flow.fetch_token(authorization_response=request.url)
    creds=flow.credentials
    token_json=creds.to_json()
    enc=encrypt_text(token_json)
    c=db()
    c.execute("UPDATE accounts SET encrypted_secret=?,connected=1,updated_at=? WHERE provider='gmail'",
      (enc,datetime.now().isoformat(timespec="seconds")))
    c.commit(); c.close()
    flash("Gmail connected successfully.")
    return redirect(url_for("connect"))

@app.post("/connect/icloud")
def connect_icloud():
    addr=request.form.get("address","").strip()
    pw=request.form.get("app_password","").strip()
    if not addr or not pw:
        flash("Enter your iCloud email and app-specific password.")
        return redirect(url_for("connect"))
    try:
        enc=encrypt_text(pw)
        # Validate immediately
        from services.icloud_service import scan_icloud
        # Avoid processing mail during connection: just login/logout here
        import imaplib, ssl
        M=imaplib.IMAP4_SSL("imap.mail.me.com",993,ssl_context=ssl.create_default_context())
        M.login(addr,pw); M.logout()
        c=db(); c.execute("UPDATE accounts SET address=?,encrypted_secret=?,connected=1,updated_at=? WHERE provider='icloud'",
            (addr,enc,datetime.now().isoformat(timespec="seconds"))); c.commit(); c.close()
        flash("iCloud Mail connected successfully.")
    except Exception as e:
        flash(f"iCloud connection failed: {e}")
    return redirect(url_for("connect"))

@app.post("/disconnect/<provider>")
def disconnect(provider):
    if provider in ("gmail","icloud"):
        c=db(); c.execute("UPDATE accounts SET address=NULL,encrypted_secret=NULL,connected=0,updated_at=? WHERE provider=?",
            (datetime.now().isoformat(timespec="seconds"),provider)); c.commit(); c.close()
        flash(f"{provider.title()} disconnected.")
    return redirect(url_for("connect"))

@app.route("/rules")
def rules():
    c=db(); rows=c.execute("SELECT * FROM senders ORDER BY status,kind,value").fetchall(); c.close()
    return render_template("rules.html",rows=rows)

@app.post("/rules/add")
def rules_add():
    value=request.form.get("value","").strip().lower().lstrip("@")
    kind=request.form.get("kind","email"); status=request.form.get("status","blocked")
    if value:
        c=db(); c.execute("""INSERT INTO senders(value,kind,status,created_at) VALUES(?,?,?,?)
            ON CONFLICT(value,kind) DO UPDATE SET status=excluded.status""",
            (value,kind,status,datetime.now().isoformat(timespec="seconds"))); c.commit(); c.close()
    return redirect(url_for("rules"))

@app.post("/rules/<int:rid>/delete")
def rules_delete(rid):
    c=db(); c.execute("DELETE FROM senders WHERE id=?",(rid,)); c.commit(); c.close()
    return redirect(url_for("rules"))

@app.route("/review")
def review():
    c=db(); rows=c.execute("SELECT * FROM quarantine WHERE status='review' ORDER BY id DESC").fetchall(); c.close()
    return render_template("review.html",rows=rows)

@app.post("/review/<int:qid>/<action>")
def review_action(qid,action):
    c=db(); r=c.execute("SELECT * FROM quarantine WHERE id=?",(qid,)).fetchone()
    if r:
        if action in ("block","allow"):
            status="blocked" if action=="block" else "allowed"
            c.execute("""INSERT INTO senders(value,kind,status,created_at) VALUES(?,?,?,?)
                ON CONFLICT(value,kind) DO UPDATE SET status=excluded.status""",
                (r["sender"].lower(),"email",status,datetime.now().isoformat(timespec="seconds")))
            c.execute("UPDATE quarantine SET status=? WHERE id=?",(status,qid))
        else:
            c.execute("UPDATE quarantine SET status='dismissed' WHERE id=?",(qid,))
        c.commit()
    c.close(); return redirect(url_for("review"))

@app.route("/settings",methods=["GET","POST"])
def settings_page():
    if request.method=="POST":
        for k in ("auto_delete_blocked_senders","auto_delete_blocked_domains","permanent_delete","auto_scan"):
            set_setting(k,"1" if request.form.get(k)=="on" else "0")
        set_setting("spam_threshold",request.form.get("spam_threshold","70"))
        set_setting("review_threshold",request.form.get("review_threshold","40"))
        flash("Settings saved.")
        return redirect(url_for("settings_page"))
    return render_template("settings.html",settings=settings_dict())

init_db()
scheduler=BackgroundScheduler(daemon=True)
scheduler.add_job(scheduled_scan,"interval",minutes=int(os.environ.get("ZULETE_SCAN_MINUTES","15")),id="mail_scan",replace_existing=True)
scheduler.start()

if __name__=="__main__":
    app.run(host="127.0.0.1",port=5055,debug=True,use_reloader=False)
