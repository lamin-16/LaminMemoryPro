#!/usr/bin/env python3
"""LaminMemoryPro v2.0.0 -- by lamin-16
AES-256-GCM | AI | Fuzzy Search | Widget | Backup | Web Dashboard
GitHub: https://github.com/lamin-16/LaminMemoryPro"""

import os, sys, json, uuid, hashlib, hmac, getpass, argparse, datetime
import subprocess, difflib, urllib.request, urllib.error, html as _esc
from pathlib import Path
from http.server import HTTPServer, BaseHTTPRequestHandler

try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.hazmat.primitives import hashes
    HAS_CRYPTO = True
except ImportError:
    HAS_CRYPTO = False

R='\033[0m'; B='\033[1m'; RED='\033[91m'; GRN='\033[92m'
YLW='\033[93m'; CYN='\033[96m'; WHT='\033[97m'
ok  = lambda m: print(f"{GRN}[OK] {m}{R}")
err = lambda m: print(f"{RED}[ERR] {m}{R}")
inf = lambda m: print(f"{CYN}[INF] {m}{R}")
wrn = lambda m: print(f"{YLW}[WRN] {m}{R}")

BANNER = (
    f"\n{CYN}{B}+================================================+\n"
    f"|  LaminMemoryPro v2.0.0  .  by lamin-16        |\n"
    f"|  AI . Fuzzy Search . Widget . Backup . Web     |\n"
    f"|  AES-256-GCM . PBKDF2-SHA256                   |\n"
    f"+================================================+{R}\n"
)

BASE  = Path.home() / ".laminmemorypro"
VAULT = BASE / "vault.enc"
META  = BASE / "meta.json"
SALT  = BASE / "salt.bin"
ITERS = 310_000

class Crypto:
    @staticmethod
    def new_salt(): return os.urandom(32)

    @staticmethod
    def derive_key(pw, salt):
        if HAS_CRYPTO:
            kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32,
                             salt=salt, iterations=ITERS)
            return kdf.derive(pw.encode())
        return hashlib.pbkdf2_hmac('sha256', pw.encode(), salt, ITERS)

    @staticmethod
    def encrypt(data, key):
        if HAS_CRYPTO:
            n = os.urandom(12)
            return n + AESGCM(key).encrypt(n, data, None)
        n  = os.urandom(16)
        ks = b''.join(hashlib.sha256(key+n+i.to_bytes(4,'big')).digest()
                      for i in range(len(data)//32+2))
        ct = bytes(a^b for a,b in zip(data, ks))
        return n + hashlib.sha256(key+n+ct).digest() + ct

    @staticmethod
    def decrypt(data, key):
        if HAS_CRYPTO:
            return AESGCM(key).decrypt(data[:12], data[12:], None)
        n,mac,ct = data[:16],data[16:48],data[48:]
        if not hmac.compare_digest(hashlib.sha256(key+n+ct).digest(), mac):
            raise ValueError("Wrong password or corrupted vault")
        ks = b''.join(hashlib.sha256(key+n+i.to_bytes(4,'big')).digest()
                      for i in range(len(ct)//32+2))
        return bytes(a^b for a,b in zip(ct, ks))

class Vault:
    def __init__(self):
        BASE.mkdir(parents=True, exist_ok=True)
        self.key = None
        self.db  = {"notes":{}, "contexts":{}, "tags":{}}

    def _save(self):
        VAULT.write_bytes(Crypto.encrypt(
            json.dumps(self.db, ensure_ascii=False).encode(), self.key))

    def setup(self, pw):
        s = Crypto.new_salt(); SALT.write_bytes(s)
        self.key = Crypto.derive_key(pw, s)
        META.write_text(json.dumps({"version":"2.0.0",
            "algo":"AES-256-GCM" if HAS_CRYPTO else "PBKDF2-XOR",
            "created":_now(),"iterations":ITERS,
            "pw_hash":hashlib.sha256(pw.encode()+s).hexdigest()},indent=2))
        self._save()
        ok(f"Vault ready  .  {'AES-256-GCM' if HAS_CRYPTO else 'PBKDF2-XOR'}  .  {ITERS:,} iters")

    def unlock(self, pw):
        if not SALT.exists() or not META.exists(): return False
        s = SALT.read_bytes(); m = json.loads(META.read_text())
        if not hmac.compare_digest(
                hashlib.sha256(pw.encode()+s).hexdigest(), m.get("pw_hash","")): return False
        self.key = Crypto.derive_key(pw, s)
        if VAULT.exists():
            try: self.db = json.loads(Crypto.decrypt(VAULT.read_bytes(), self.key))
            except: return False
        return True

    def add_note(self, title, content, tags=None):
        nid = uuid.uuid4().hex[:8]
        self.db["notes"][nid] = {"id":nid,"title":title,"content":content,
            "tags":tags or [],"created":_now(),"modified":_now()}
        for t in (tags or []): self.db["tags"].setdefault(t,[]).append(nid)
        self._save(); return nid

    def del_note(self, nid):
        n = self.db["notes"].pop(nid, None)
        if not n: return False
        for t in n.get("tags",[]):
            lst = self.db["tags"].get(t,[])
            if nid in lst: lst.remove(nid)
        self._save(); return True

    def set_ctx(self, name, data):
        cid = uuid.uuid4().hex[:8]
        self.db["contexts"][name] = {"id":cid,"name":name,"data":data,
                                     "created":_now(),"modified":_now()}
        self._save(); return cid

    def export(self, path):
        Path(path).write_text(json.dumps(self.db, indent=2, ensure_ascii=False))
        ok(f"Exported -> {path}")

    def stats(self):
        return len(self.db["notes"]),len(self.db["contexts"]),len(self.db["tags"])

def _now(): return datetime.datetime.now().isoformat()
def _pw(p="Master Password: "): return getpass.getpass(p)
def _ready(): return SALT.exists() and META.exists()

def _open(pw=None):
    if not _ready(): err("No vault. Run: python lamin_memory.py init"); sys.exit(1)
    v = Vault()
    if not v.unlock(pw or _pw()): err("Wrong password!"); sys.exit(1)
    return v

def cmd_init(a):
    if _ready():
        wrn("Vault exists. Type YES to overwrite:")
        if input("> ").strip() != "YES": inf("Aborted."); return
    p1 = _pw("New Master Password (min 8): ")
    p2 = _pw("Confirm: ")
    if p1 != p2: err("No match!"); return
    if len(p1) < 8: err("Min 8 chars!"); return
    Vault().setup(p1)

def cmd_add(a):
    v = _open()
    t = a.title or input(f"{YLW}Title: {R}")
    if a.content:
        c = a.content
    else:
        print(f"{YLW}Content (empty line to finish):{R}")
        ls = []
        while True:
            l = input()
            if not l and ls: break
            ls.append(l)
        c = "\n".join(ls)
    tags = [x.strip() for x in (a.tags or "").split(",") if x.strip()]
    ok(f"Saved -> ID: {B}{v.add_note(t, c, tags)}{R}")

def cmd_list(a):
    v  = _open()
    ns = sorted(v.db["notes"].values(), key=lambda x: x["created"], reverse=True)
    if not ns: inf("No notes."); return
    print(f"\n{B}{CYN}{'ID':<10}{'TITLE':<30}{'TAGS':<18}CREATED{R}\n"+"-"*70)
    for n in ns:
        tg = ",".join(n.get("tags",[])[:2]) or "--"
        ti = (n["title"][:27]+"...") if len(n["title"])>28 else n["title"]
        print(f"{GRN}{n['id']:<10}{R}{ti:<30}{YLW}{tg:<18}{R}{n['created'][:10]}")
    print(f"\n{CYN}Total: {len(ns)}{R}\n")

def cmd_show(a):
    v = _open(); n = v.db["notes"].get(a.id)
    if not n: err(f"'{a.id}' not found."); return
    sep = f"{CYN}{'='*52}{R}"
    print(f"\n{sep}\n{B}ID:      {GRN}{n['id']}{R}\n{B}Title:   {WHT}{n['title']}{R}")
    print(f"{B}Tags:    {YLW}{', '.join(n.get('tags',[])) or '--'}{R}")
    print(f"{B}Created: {R}{n['created'][:19]}\n{CYN}{'-'*52}{R}\n{n['content']}\n{sep}\n")

def cmd_delete(a):
    v = _open()
    if v.del_note(a.id): ok(f"Deleted: {a.id}")
    else: err(f"Not found: {a.id}")

def cmd_search(a):
    v = _open(); q = a.query.lower(); results = []
    for n in v.db["notes"].values():
        exact = (q in n["title"].lower() or q in n["content"].lower()
                 or any(q in t.lower() for t in n.get("tags",[])))
        if exact:
            results.append((n, 1.0))
        else:
            ts = difflib.SequenceMatcher(None, q, n["title"].lower()).ratio()
            cs = difflib.SequenceMatcher(None, q, n["content"].lower()[:200]).ratio()
            score = max(ts, cs * 0.8)
            if score >= 0.55: results.append((n, score))
    results.sort(key=lambda x: x[1], reverse=True)
    if not results: inf(f"No results for '{a.query}'."); return
    print(f"\n{CYN}Found {len(results)} result(s):{R}\n")
    for n, score in results:
        tg = ",".join(n.get("tags",[])) or "--"
        print(f"  {GRN}[{n['id']}]{R} {B}{n['title']}{R}  {YLW}{tg}{R}  {CYN}{score*100:.0f}% match{R}")
        print(f"  {n['content'][:80].replace(chr(10),' ')}...\n")

def cmd_ctx_add(a):
    v = _open()
    print(f"{YLW}Value (JSON or plain text):{R}"); raw = input()
    try: data = json.loads(raw)
    except: data = {"value": raw}
    ok(f"Context '{a.name}' saved (ID: {v.set_ctx(a.name, data)})")

def cmd_ctx_list(a):
    v = _open(); cs = list(v.db["contexts"].values())
    if not cs: inf("No contexts."); return
    print(f"\n{B}{CYN}{'NAME':<26}{'ID':<10}CREATED{R}\n"+"-"*50)
    for c in cs: print(f"{GRN}{c['name']:<26}{R}{c['id']:<10}{c['created'][:10]}")
    print()

def cmd_ctx_show(a):
    v = _open(); c = v.db["contexts"].get(a.name)
    if not c: err(f"'{a.name}' not found."); return
    print(f"\n{CYN}Context: {B}{c['name']}{R}\n{json.dumps(c['data'], indent=2)}")

def cmd_export(a):
    v = _open()
    v.export(a.path or f"lamin_export_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.json")

def cmd_stats(a):
    v = _open(); notes,ctxs,tags = v.stats(); m = json.loads(META.read_text())
    rows = [("Notes",notes,WHT),("Contexts",ctxs,WHT),("Tags",tags,WHT),
            ("Algorithm",m.get("algo","?"),GRN),("Iterations",f"{m.get('iterations',0):,}",WHT)]
    print(f"\n{B}{CYN}  -- LaminMemoryPro v2.0.0 Stats --{R}")
    for lbl,val,col in rows: print(f"  {YLW}{lbl:<14}{col}{val}{R}")
    print()

def cmd_ai(a):
    v = _open()
    ctx = v.db["contexts"].get("claude_api_key")
    if not ctx:
        err("No API key set.")
        inf("Run: python lamin_memory.py ctx add claude_api_key")
        inf('Enter: {"key": "sk-ant-api03-..."}')
        return
    api_key = ctx["data"].get("key","")
    notes   = list(v.db["notes"].values())
    context = "\n\n".join(
        f"[{n['id']}] {n['title']}\nTags: {','.join(n.get('tags',[]))}\n{n['content']}"
        for n in notes[:15])
    question = a.question or input(f"{YLW}Ask Claude about your notes: {R}")
    payload  = json.dumps({"model":"claude-sonnet-4-6","max_tokens":1024,
        "messages":[{"role":"user","content":
            f"My memory notes:\n\n{context}\n\nQuestion: {question}"}]}).encode()
    req = urllib.request.Request("https://api.anthropic.com/v1/messages",
        data=payload, headers={"Content-Type":"application/json",
        "x-api-key":api_key,"anthropic-version":"2023-06-01"})
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            ans = json.loads(r.read())["content"][0]["text"]
            print(f"\n{CYN}{B}Claude:{R}\n{ans}\n")
            if getattr(a,"save",False):
                nid = v.add_note(f"AI: {question[:40]}", ans, ["ai","claude"])
                ok(f"Answer saved as note -> {nid}")
    except urllib.error.HTTPError as e:
        err(f"API {e.code}: {e.read().decode()[:200]}")
    except Exception as e:
        err(f"Error: {e}")

def cmd_widget(a):
    sd = Path.home() / ".shortcuts"; sd.mkdir(exist_ok=True)
    proj = Path.home() / "LaminMemoryPro"
    sh = "#!/data/data/com.termux/files/usr/bin/bash"
    widgets = {
        "LaminAdd":    f"{sh}\ncd {proj}\npython lamin_memory.py add\n",
        "LaminList":   f"{sh}\ncd {proj}\npython lamin_memory.py list\nread -p 'Press Enter...'\n",
        "LaminBackup": f"{sh}\ncd {proj}\npython lamin_memory.py backup\n",
        "LaminWeb":    f"{sh}\ncd {proj}\npython lamin_memory.py web\n",
    }
    for name,body in widgets.items():
        s = sd/name; s.write_text(body); s.chmod(0o755)
        ok(f"Widget created: ~/.shortcuts/{name}")
    inf("1. Install Termux:Widget from F-Droid")
    inf("2. Long-press homescreen -> Widgets -> Termux:Widget")
    inf("3. Select: LaminAdd / LaminList / LaminBackup / LaminWeb")

def cmd_backup(a):
    _open()
    proj = Path.home() / "LaminMemoryPro"
    if not (proj / ".git").exists():
        err(f"No .git repo at {proj}"); return
    os.chdir(proj)
    ts = datetime.datetime.now().strftime("%Y-%m-%d %H:%M")
    for cmd,label in [
        (["git","add","-A"],                    "Staging"),
        (["git","commit","-m",f"backup: {ts}"], "Committing"),
        (["git","push"],                         "Pushing to GitHub"),
    ]:
        inf(f"{label}...")
        r = subprocess.run(cmd, capture_output=True, text=True)
        if r.returncode == 0: ok(f"{label} done")
        elif "nothing to commit" in r.stdout+r.stderr: inf("Nothing new to commit")
        else: err(r.stderr.strip() or r.stdout.strip()); return
    ok("GitHub backup complete!")

_PAGE = (
    "<!DOCTYPE html><html><head>"
    "<meta charset=UTF-8><meta name=viewport content='width=device-width,initial-scale=1'>"
    "<title>LaminMemoryPro</title><style>"
    "*{box-sizing:border-box;margin:0;padding:0}"
    "body{background:#0d1117;color:#e6edf3;font-family:monospace;padding:16px}"
    "h1{color:#58a6ff;margin-bottom:4px}"
    ".sub{color:#8b949e;font-size:12px;margin-bottom:16px}"
    "input{width:100%;padding:10px;background:#161b22;border:1px solid #30363d;"
    "color:#e6edf3;border-radius:6px;margin-bottom:16px;font-size:14px}"
    ".card{background:#161b22;border:1px solid #30363d;border-radius:8px;"
    "padding:14px;margin-bottom:10px}"
    ".cid{color:#3fb950;font-size:11px}.ctitle{font-size:15px;font-weight:bold;margin:5px 0}"
    ".ctags{margin-bottom:8px}.tag{background:#1f6feb;color:#fff;padding:1px 7px;"
    "border-radius:10px;font-size:11px;margin-right:3px}"
    ".cbody{color:#8b949e;font-size:12px;white-space:pre-wrap}"
    ".cdate{color:#484f58;font-size:10px;margin-top:8px}"
    "</style></head><body>"
    "<h1>&#128274; LaminMemoryPro</h1>"
    "<div class=sub>%%STATS%%</div>"
    "<input id=q placeholder='Search notes...' oninput='f()'>"
    "<div id=notes>%%NOTES%%</div>"
    "<script>function f(){var q=document.getElementById('q').value.toLowerCase();"
    "document.querySelectorAll('.card').forEach(function(c){"
    "c.style.display=c.textContent.toLowerCase().includes(q)?'':'none'})}"
    "</script></body></html>"
)

class _Handler(BaseHTTPRequestHandler):
    vault = None
    def log_message(self, *a): pass
    def do_GET(self):
        v  = _Handler.vault
        ns = sorted(v.db["notes"].values(), key=lambda x: x["created"], reverse=True)
        nc,cc,tc = v.stats()
        stats = f"Notes: {nc} | Contexts: {cc} | Tags: {tc} | AES-256-GCM | v2.0.0"
        cards = ""
        for n in ns:
            tgs  = "".join(f'<span class="tag">{_esc.escape(t)}</span>'
                           for t in n.get("tags",[]))
            body = _esc.escape(n["content"][:250]+("..." if len(n["content"])>250 else ""))
            cards += (f'<div class="card"><div class="cid">[{n["id"]}]</div>'
                      f'<div class="ctitle">{_esc.escape(n["title"])}</div>'
                      f'<div class="ctags">{tgs or "<span style=color:#484f58>no tags</span>"}</div>'
                      f'<div class="cbody">{body}</div>'
                      f'<div class="cdate">{n["created"][:19]}</div></div>')
        page = _PAGE.replace("%%STATS%%",stats).replace("%%NOTES%%",cards)
        self.send_response(200); self.send_header("Content-type","text/html;charset=utf-8")
        self.end_headers(); self.wfile.write(page.encode())

def cmd_web(a):
    v = _open(); port = int(getattr(a,"port",8765) or 8765)
    _Handler.vault = v; srv = HTTPServer(("127.0.0.1",port), _Handler)
    ok(f"Dashboard  ->  http://127.0.0.1:{port}")
    inf("Open: termux-open-url http://127.0.0.1:8765")
    inf("Stop: Ctrl+C")
    try: srv.serve_forever()
    except KeyboardInterrupt: inf("Server stopped.")

def main():
    print(BANNER)
    if not HAS_CRYPTO:
        wrn("cryptography missing. Fix: pkg install python-cryptography\n")
    P = argparse.ArgumentParser(prog="lamin_memory.py",
        description="LaminMemoryPro v2.0.0")
    S = P.add_subparsers(dest="cmd")
    for name in ("init","list","stats","backup","widget"): S.add_parser(name)
    pa=S.add_parser("add"); pa.add_argument("-t","--title"); pa.add_argument("-c","--content"); pa.add_argument("--tags")
    ps=S.add_parser("show"); ps.add_argument("id")
    pd=S.add_parser("delete"); pd.add_argument("id")
    pq=S.add_parser("search"); pq.add_argument("query")
    pai=S.add_parser("ai"); pai.add_argument("question",nargs="?"); pai.add_argument("-s","--save",action="store_true")
    pex=S.add_parser("export"); pex.add_argument("-o","--path")
    pw=S.add_parser("web"); pw.add_argument("-p","--port",default=8765)
    pc=S.add_parser("ctx"); cs=pc.add_subparsers(dest="ctx_cmd")
    pca=cs.add_parser("add"); pca.add_argument("name"); cs.add_parser("list")
    pcs=cs.add_parser("show"); pcs.add_argument("name")
    a = P.parse_args()
    if not a.cmd: P.print_help(); return
    dispatch={"init":cmd_init,"add":cmd_add,"list":cmd_list,"show":cmd_show,
        "delete":cmd_delete,"search":cmd_search,"export":cmd_export,"stats":cmd_stats,
        "ai":cmd_ai,"widget":cmd_widget,"backup":cmd_backup,"web":cmd_web}
    if a.cmd=="ctx":
        if not getattr(a,"ctx_cmd",None): pc.print_help(); return
        {"add":cmd_ctx_add,"list":cmd_ctx_list,"show":cmd_ctx_show}.get(a.ctx_cmd,lambda _:None)(a)
    else:
        dispatch.get(a.cmd,lambda _:P.print_help())(a)

if __name__=="__main__": main()
