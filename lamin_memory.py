#!/usr/bin/env python3
"""
LaminMemoryPro v1.0.0 -- by lamin-16
Secure AI Memory & Context Management System
AES-256-GCM | PBKDF2-SHA256 | Termux-Ready
GitHub: https://github.com/lamin-16/LaminMemoryPro
"""

import os, sys, json, uuid, hashlib, hmac, getpass, argparse, datetime
from pathlib import Path

try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.hazmat.primitives import hashes
    HAS_CRYPTO = True
except ImportError:
    HAS_CRYPTO = False

R   = '\033[0m';  B   = '\033[1m'
RED = '\033[91m'; GRN = '\033[92m'
YLW = '\033[93m'; CYN = '\033[96m'; WHT = '\033[97m'

ok  = lambda m: print(f"{GRN}[OK] {m}{R}")
err = lambda m: print(f"{RED}[ERR] {m}{R}")
inf = lambda m: print(f"{CYN}[INF] {m}{R}")
wrn = lambda m: print(f"{YLW}[WRN] {m}{R}")

BANNER = (
    f"\n{CYN}{B}+----------------------------------------------+\n"
    f"|   LaminMemoryPro v1.0.0  .  by lamin-16     |\n"
    f"|   Secure AI Memory & Context Manager         |\n"
    f"|   AES-256-GCM . PBKDF2-SHA256               |\n"
    f"+----------------------------------------------+{R}\n"
)

BASE  = Path.home() / ".laminmemorypro"
VAULT = BASE / "vault.enc"
META  = BASE / "meta.json"
SALT  = BASE / "salt.bin"
ITERS = 310_000

class Crypto:
    @staticmethod
    def new_salt() -> bytes:
        return os.urandom(32)

    @staticmethod
    def derive_key(pw: str, salt: bytes) -> bytes:
        if HAS_CRYPTO:
            kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32,
                             salt=salt, iterations=ITERS)
            return kdf.derive(pw.encode())
        return hashlib.pbkdf2_hmac('sha256', pw.encode(), salt, ITERS)

    @staticmethod
    def encrypt(data: bytes, key: bytes) -> bytes:
        if HAS_CRYPTO:
            n = os.urandom(12)
            return n + AESGCM(key).encrypt(n, data, None)
        n  = os.urandom(16)
        ks = b''.join(hashlib.sha256(key + n + i.to_bytes(4, 'big')).digest()
                      for i in range(len(data) // 32 + 2))
        ct  = bytes(a ^ b for a, b in zip(data, ks))
        mac = hashlib.sha256(key + n + ct).digest()
        return n + mac + ct

    @staticmethod
    def decrypt(data: bytes, key: bytes) -> bytes:
        if HAS_CRYPTO:
            return AESGCM(key).decrypt(data[:12], data[12:], None)
        n, mac, ct = data[:16], data[16:48], data[48:]
        exp = hashlib.sha256(key + n + ct).digest()
        if not hmac.compare_digest(mac, exp):
            raise ValueError("Integrity check failed -- wrong password or corrupted vault")
        ks = b''.join(hashlib.sha256(key + n + i.to_bytes(4, 'big')).digest()
                      for i in range(len(ct) // 32 + 2))
        return bytes(a ^ b for a, b in zip(ct, ks))

class Vault:
    def __init__(self):
        BASE.mkdir(parents=True, exist_ok=True)
        self.key = None
        self.db  = {"notes": {}, "contexts": {}, "tags": {}}

    def _persist(self):
        raw = json.dumps(self.db, ensure_ascii=False).encode()
        VAULT.write_bytes(Crypto.encrypt(raw, self.key))

    def setup(self, pw: str):
        s = Crypto.new_salt()
        SALT.write_bytes(s)
        self.key = Crypto.derive_key(pw, s)
        META.write_text(json.dumps({
            "version":    "1.0.0",
            "algo":       "AES-256-GCM" if HAS_CRYPTO else "PBKDF2-XOR-SHA256",
            "created":    _now(), "iterations": ITERS,
            "pw_hash":    hashlib.sha256(pw.encode() + s).hexdigest()
        }, indent=2))
        self._persist()
        algo = "AES-256-GCM" if HAS_CRYPTO else "PBKDF2-XOR"
        ok(f"Vault ready  .  {algo}  .  PBKDF2 {ITERS:,} iters")

    def unlock(self, pw: str) -> bool:
        if not SALT.exists() or not META.exists(): return False
        s = SALT.read_bytes()
        m = json.loads(META.read_text())
        if not hmac.compare_digest(
                hashlib.sha256(pw.encode() + s).hexdigest(), m.get("pw_hash", "")):
            return False
        self.key = Crypto.derive_key(pw, s)
        if VAULT.exists():
            try: self.db = json.loads(Crypto.decrypt(VAULT.read_bytes(), self.key))
            except Exception: return False
        return True

    def add_note(self, title, content, tags=None):
        nid = uuid.uuid4().hex[:8]
        self.db["notes"][nid] = {
            "id": nid, "title": title, "content": content,
            "tags": tags or [], "created": _now(), "modified": _now()
        }
        for tag in (tags or []): self.db["tags"].setdefault(tag, []).append(nid)
        self._persist(); return nid

    def delete_note(self, nid):
        n = self.db["notes"].pop(nid, None)
        if not n: return False
        for tag in n.get("tags", []):
            lst = self.db["tags"].get(tag, [])
            if nid in lst: lst.remove(nid)
        self._persist(); return True

    def search(self, query):
        q = query.lower()
        return [n for n in self.db["notes"].values()
                if q in n["title"].lower() or q in n["content"].lower()
                or any(q in t.lower() for t in n.get("tags", []))]

    def set_context(self, name, data):
        cid = uuid.uuid4().hex[:8]
        self.db["contexts"][name] = {
            "id": cid, "name": name, "data": data,
            "created": _now(), "modified": _now()
        }
        self._persist(); return cid

    def export(self, path):
        Path(path).write_text(json.dumps(self.db, indent=2, ensure_ascii=False))
        ok(f"Exported  ->  {path}")

    def stats(self):
        return len(self.db["notes"]), len(self.db["contexts"]), len(self.db["tags"])

def _now():   return datetime.datetime.now().isoformat()
def _pw(p="Master Password: "): return getpass.getpass(p)
def _ready(): return SALT.exists() and META.exists()

def _open(pw=None):
    if not _ready(): err("No vault found.  Run:  python lamin_memory.py init"); sys.exit(1)
    v = Vault()
    if not v.unlock(pw or _pw()): err("Wrong password!"); sys.exit(1)
    return v

def cmd_init(a):
    if _ready():
        wrn("Vault exists. Type YES to overwrite:")
        if input("> ").strip() != "YES": inf("Aborted."); return
    p1 = _pw("New Master Password (min 8 chars): ")
    p2 = _pw("Confirm: ")
    if p1 != p2: err("Passwords do not match!"); return
    if len(p1) < 8: err("Minimum 8 characters!"); return
    Vault().setup(p1)

def cmd_add(a):
    v = _open()
    title = a.title or input(f"{YLW}Title: {R}")
    if a.content:
        content = a.content
    else:
        print(f"{YLW}Content (empty line to finish):{R}")
        lines = []
        while True:
            line = input()
            if not line and lines: break
            lines.append(line)
        content = "\n".join(lines)
    tags = [x.strip() for x in (a.tags or "").split(",") if x.strip()]
    nid  = v.add_note(title, content, tags)
    ok(f"Note saved  ->  ID: {B}{nid}{R}")

def cmd_list(a):
    v  = _open()
    ns = sorted(v.db["notes"].values(), key=lambda x: x["created"], reverse=True)
    if not ns: inf("No notes yet."); return
    print(f"\n{B}{CYN}{'ID':<10}{'TITLE':<30}{'TAGS':<18}CREATED{R}")
    print("-" * 70)
    for n in ns:
        tg = ",".join(n.get("tags", [])[:2]) or "--"
        ti = (n["title"][:27] + "...") if len(n["title"]) > 28 else n["title"]
        print(f"{GRN}{n['id']:<10}{R}{ti:<30}{YLW}{tg:<18}{R}{n['created'][:10]}")
    print(f"\n{CYN}Total: {len(ns)} note(s){R}\n")

def cmd_show(a):
    v = _open()
    n = v.db["notes"].get(a.id)
    if not n: err(f"Note '{a.id}' not found."); return
    sep = f"{CYN}{'=' * 52}{R}"
    print(f"\n{sep}")
    print(f"{B}ID:      {GRN}{n['id']}{R}")
    print(f"{B}Title:   {WHT}{n['title']}{R}")
    print(f"{B}Tags:    {YLW}{', '.join(n.get('tags', [])) or '--'}{R}")
    print(f"{B}Created: {R}{n['created'][:19]}")
    print(f"{CYN}{'-' * 52}{R}\n{n['content']}\n{sep}\n")

def cmd_delete(a):
    v = _open()
    if v.delete_note(a.id): ok(f"Deleted: {a.id}")
    else: err(f"Note '{a.id}' not found.")

def cmd_search(a):
    v  = _open()
    rs = v.search(a.query)
    if not rs: inf(f"No results for '{a.query}'."); return
    print(f"\n{CYN}{len(rs)} result(s):{R}\n")
    for n in rs:
        tg = ",".join(n.get("tags", [])) or "--"
        print(f"  {GRN}[{n['id']}]{R} {B}{n['title']}{R}  {YLW}{tg}{R}")
        sn = n["content"][:80].replace("\n", " ")
        print(f"  {sn}{'...' if len(n['content']) > 80 else ''}\n")

def cmd_ctx_add(a):
    v = _open()
    print(f"{YLW}Context value (JSON or plain text):{R}")
    raw = input()
    try: data = json.loads(raw)
    except Exception: data = {"value": raw}
    cid = v.set_context(a.name, data)
    ok(f"Context '{a.name}' saved  (ID: {cid})")

def cmd_ctx_list(a):
    v  = _open()
    cs = list(v.db["contexts"].values())
    if not cs: inf("No contexts yet."); return
    print(f"\n{B}{CYN}{'NAME':<26}{'ID':<10}CREATED{R}")
    print("-" * 50)
    for c in cs: print(f"{GRN}{c['name']:<26}{R}{c['id']:<10}{c['created'][:10]}")
    print()

def cmd_ctx_show(a):
    v = _open()
    c = v.db["contexts"].get(a.name)
    if not c: err(f"Context '{a.name}' not found."); return
    print(f"\n{CYN}Context: {B}{c['name']}{R}")
    print(json.dumps(c["data"], indent=2, ensure_ascii=False))

def cmd_export(a):
    v = _open()
    p = a.path or f"lamin_export_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    v.export(p)

def cmd_stats(a):
    v = _open()
    notes, ctxs, tags = v.stats()
    m = json.loads(META.read_text())
    rows = [
        ("Notes",      notes,                        WHT),
        ("Contexts",   ctxs,                         WHT),
        ("Tags",       tags,                         WHT),
        ("Algorithm",  m.get("algo", "?"),            GRN),
        ("Iterations", f"{m.get('iterations', 0):,}", WHT),
        ("Created",    m.get("created", "?")[:10],    WHT),
    ]
    print(f"\n{B}{CYN}  -- LaminMemoryPro Vault Stats --{R}")
    for lbl, val, col in rows: print(f"  {YLW}{lbl:<14}{col}{val}{R}")
    print()

def main():
    print(BANNER)
    if not HAS_CRYPTO:
        wrn("'cryptography' not installed -- using built-in fallback.")
        wrn("Upgrade: pip install cryptography\n")
    P = argparse.ArgumentParser(prog="lamin_memory.py",
        description="LaminMemoryPro -- Secure AI Memory & Context Manager")
    S = P.add_subparsers(dest="cmd")
    S.add_parser("init",  help="Initialize new encrypted vault")
    S.add_parser("list",  help="List all notes")
    S.add_parser("stats", help="Show vault statistics")
    pa = S.add_parser("add", help="Add a new note")
    pa.add_argument("-t", "--title"); pa.add_argument("-c", "--content")
    pa.add_argument("--tags", help="Comma-separated tags")
    ps  = S.add_parser("show",   help="Show note");   ps.add_argument("id")
    pd  = S.add_parser("delete", help="Delete note"); pd.add_argument("id")
    pq  = S.add_parser("search", help="Search");      pq.add_argument("query")
    pex = S.add_parser("export", help="Export to JSON"); pex.add_argument("-o","--path")
    pc  = S.add_parser("ctx", help="Manage AI contexts")
    cs  = pc.add_subparsers(dest="ctx_cmd")
    pca = cs.add_parser("add");  pca.add_argument("name")
    cs.add_parser("list")
    pcs = cs.add_parser("show"); pcs.add_argument("name")
    a = P.parse_args()
    if not a.cmd: P.print_help(); return
    dispatch = {
        "init":   cmd_init,  "add":    cmd_add,    "list":   cmd_list,
        "show":   cmd_show,  "delete": cmd_delete,  "search": cmd_search,
        "export": cmd_export,"stats":  cmd_stats,
    }
    if a.cmd == "ctx":
        if not getattr(a, "ctx_cmd", None): pc.print_help(); return
        {"add": cmd_ctx_add, "list": cmd_ctx_list, "show": cmd_ctx_show
         }.get(a.ctx_cmd, lambda _: None)(a)
    else:
        dispatch.get(a.cmd, lambda _: P.print_help())(a)

if __name__ == "__main__":
    main()
