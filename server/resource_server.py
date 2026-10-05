#!/usr/bin/env python3
"""Immutable resource package server, admin CLI and web console.

The server has no third-party Python dependencies. SQLite provides relational
file identities, package membership, device groups, releases and GC reference
counts.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import http.server
import json
import os
import shutil
import sqlite3
import struct
import sys
import threading
import time
import urllib.parse
import zlib
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DEFAULT_STATE = ROOT / "state"
SCHEMA = r'''
PRAGMA foreign_keys=ON;
CREATE TABLE IF NOT EXISTS files (
  sha256 TEXT PRIMARY KEY CHECK(length(sha256)=64),
  media_type TEXT NOT NULL,
  size_bytes INTEGER NOT NULL CHECK(size_bytes>=0),
  width INTEGER CHECK(width IS NULL OR width>0),
  height INTEGER CHECK(height IS NULL OR height>0),
  created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS packages (
  package_id TEXT PRIMARY KEY CHECK(length(package_id)=64),
  version TEXT NOT NULL UNIQUE,
  package_size INTEGER NOT NULL CHECK(package_size>0),
  manifest_sha256 TEXT NOT NULL REFERENCES files(sha256),
  created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS package_files (
  package_id TEXT NOT NULL REFERENCES packages(package_id) ON DELETE CASCADE,
  sha256 TEXT NOT NULL REFERENCES files(sha256),
  logical_path TEXT NOT NULL,
  media_type TEXT NOT NULL,
  size_bytes INTEGER NOT NULL,
  width INTEGER, height INTEGER,
  layout_dependencies TEXT NOT NULL DEFAULT '[]',
  required INTEGER NOT NULL DEFAULT 1,
  PRIMARY KEY(package_id, logical_path),
  UNIQUE(package_id, sha256)
);
CREATE TABLE IF NOT EXISTS device_groups (
  group_id TEXT PRIMARY KEY,
  display_name TEXT NOT NULL,
  created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS devices (
  device_id TEXT PRIMARY KEY,
  group_id TEXT REFERENCES device_groups(group_id),
  display_name TEXT NOT NULL,
  enrolled_at TEXT NOT NULL,
  last_seen_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS group_releases (
  group_id TEXT NOT NULL REFERENCES device_groups(group_id),
  release_id TEXT NOT NULL,
  package_id TEXT NOT NULL REFERENCES packages(package_id),
  state TEXT NOT NULL CHECK(state IN ('pending','current','rollback')),
  created_at TEXT NOT NULL,
  activated_at TEXT,
  superseded_at TEXT,
  retained_until TEXT,
  PRIMARY KEY(group_id, release_id)
);
CREATE TABLE IF NOT EXISTS device_events (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  device_id TEXT NOT NULL REFERENCES devices(device_id),
  group_id TEXT NOT NULL,
  release_id TEXT NOT NULL,
  package_id TEXT NOT NULL,
  status TEXT NOT NULL,
  message TEXT,
  created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS missing_reports (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  device_id TEXT, logical_path TEXT NOT NULL,
  expected_sha256 TEXT, reason TEXT NOT NULL,
  created_at TEXT NOT NULL
);
CREATE TRIGGER IF NOT EXISTS package_files_after_insert AFTER INSERT ON package_files
BEGIN UPDATE files SET ref_count=(SELECT COUNT(*) FROM package_files WHERE sha256=NEW.sha256)
 WHERE sha256=NEW.sha256; END;
CREATE TRIGGER IF NOT EXISTS package_files_after_delete AFTER DELETE ON package_files
BEGIN UPDATE files SET ref_count=(SELECT COUNT(*) FROM package_files WHERE sha256=OLD.sha256)
 WHERE sha256=OLD.sha256; END;
'''
# SQLite ALTER is used below to add ref_count for fresh/existing databases.


def now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def safe_relative(path: str) -> bool:
    if not path or path.startswith(("/", "\\")) or "\\" in path or ":" in path:
        return False
    p = Path(path)
    if p.is_absolute() or any(part in ("", ".", "..") for part in p.parts):
        return False
    return all(ord(c) >= 32 for c in path)


def connect(state_dir: Path) -> sqlite3.Connection:
    state_dir.mkdir(parents=True, exist_ok=True)
    db = state_dir / "resource.db"
    con = sqlite3.connect(db)
    con.row_factory = sqlite3.Row
    con.execute("PRAGMA foreign_keys=ON")
    con.execute("PRAGMA journal_mode=WAL")
    con.executescript(SCHEMA)
    try:
        con.execute("ALTER TABLE files ADD COLUMN ref_count INTEGER NOT NULL DEFAULT 0")
    except sqlite3.OperationalError:
        pass
    con.execute("UPDATE files SET ref_count=(SELECT COUNT(*) FROM package_files WHERE package_files.sha256=files.sha256)")
    con.commit()
    return con


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def canonical_manifest(entries: list[dict], version: str) -> tuple[bytes, str]:
    docs = []
    for e in sorted(entries, key=lambda x: x["path"]):
        docs.append({
            "path": e["path"], "sha256": e["sha256"], "media_type": e["media_type"],
            "size": e["size"], "width": e.get("width"), "height": e.get("height"),
            "layout_dependencies": e.get("layout_dependencies", []),
            "required": bool(e.get("required", True)),
        })
    data = json.dumps({"format": "resource-manifest/1", "version": version,
                       "files": docs}, ensure_ascii=False, indent=2, sort_keys=True).encode()
    return data + b"\n", hashlib.sha256(data + b"\n").hexdigest()


def image_dimensions(path: Path, media_type: str) -> tuple[int | None, int | None]:
    if media_type == "image/png":
        with path.open("rb") as f:
            data = f.read(24)
        if len(data) >= 24 and data[:8] == b"\x89PNG\r\n\x1a\n":
            return struct.unpack(">II", data[16:24])
    if media_type == "image/svg+xml":
        text = path.read_text(encoding="utf-8", errors="ignore")
        import re
        m = re.search(r'\bwidth="\s*([0-9]+)', text)
        n = re.search(r'\bheight="\s*([0-9]+)', text)
        if m and n:
            return int(m.group(1)), int(n.group(1))
    return None, None


def make_png(width: int, height: int, rgba: tuple[int, int, int, int]) -> bytes:
    raw = b"".join(b"\x00" + bytes(rgba) * width for _ in range(height))
    def chunk(kind: bytes, data: bytes) -> bytes:
        return struct.pack(">I", len(data)) + kind + data + struct.pack(">I", zlib.crc32(kind + data) & 0xffffffff)
    png = b"\x89PNG\r\n\x1a\n"
    png += chunk(b"IHDR", struct.pack(">IIBBBBB", width, height, 8, 6, 0, 0, 0))
    png += chunk(b"IDAT", zlib.compress(raw, 9))
    png += chunk(b"IEND", b"")
    return png


def materialize_demo_sources() -> None:
    base = ROOT / "resources"
    v1 = base / "source-v1"
    v2 = base / "source-v2"
    for d in [v1 / "backgrounds", v1 / "fonts", v1 / "icons",
              v2 / "backgrounds", v2 / "fonts", v2 / "icons"]:
        d.mkdir(parents=True, exist_ok=True)
    bg1 = v1 / "backgrounds" / "background.png"
    if not bg1.exists():
        shutil.copyfile(ROOT / "assets" / "background.png", bg1)
    font = b"BUILTIN-FALLBACK-LAYOUT\nfont-family: terminal-fallback; units: px\n"
    icon = b'<svg xmlns="http://www.w3.org/2000/svg" width="64" height="64" viewBox="0 0 64 64"><rect width="64" height="64" rx="12" fill="#2563eb"/><circle cx="32" cy="32" r="18" fill="#fff"/></svg>\n'
    for d in (v1, v2):
        (d / "fonts" / "terminal.fnt").write_bytes(font)
        (d / "icons" / "status.svg").write_bytes(icon)
    (v2 / "backgrounds" / "background.png").write_bytes(make_png(1280, 720, (20, 83, 120, 255)))
    def manifest(src: Path, version: str):
        m = {"version": version, "files": [
            {"path": "backgrounds/background.png", "media_type": "image/png",
             "width": 1280 if version == "2.0.0" else None,
             "height": 720 if version == "2.0.0" else None,
             "layout_dependencies": ["window:1280x720", "theme:dark"]},
            {"path": "fonts/terminal.fnt", "media_type": "application/x-terminal-font",
             "layout_dependencies": ["ui:basic-operations"]},
            {"path": "icons/status.svg", "media_type": "image/svg+xml", "width": 64, "height": 64,
             "layout_dependencies": ["ui:status-panel"]},
        ]}
        (src / "manifest.input.json").write_text(json.dumps(m, ensure_ascii=False, indent=2), encoding="utf-8")
    manifest(v1, "1.0.0"); manifest(v2, "2.0.0")


def build_package(state_dir: Path, source_dir: Path, version: str) -> str:
    source_dir = source_dir.resolve()
    input_path = source_dir / "manifest.input.json"
    if not input_path.is_file():
        raise SystemExit(f"missing manifest: {input_path}")
    spec = json.loads(input_path.read_text(encoding="utf-8"))
    entries = []
    for item in spec["files"]:
        logical = item["path"]
        if not safe_relative(logical):
            raise SystemExit(f"unsafe logical path: {logical}")
        src = (source_dir / logical).resolve()
        try:
            src.relative_to(source_dir)
        except ValueError:
            raise SystemExit(f"file escapes source root: {logical}")
        if not src.is_file():
            raise SystemExit(f"missing source file: {logical}")
        e = dict(item)
        e["sha256"] = sha256_file(src)
        e["size"] = src.stat().st_size
        if not e.get("width") or not e.get("height"):
            e["width"], e["height"] = image_dimensions(src, e["media_type"])
        entries.append(e)
    manifest_bytes, manifest_sha = canonical_manifest(entries, version)
    manifest_entry = {"path": "manifest.json", "sha256": manifest_sha,
                      "media_type": "application/json", "size": len(manifest_bytes),
                      "layout_dependencies": [], "required": True}
    # Parser finds manifest.json independently; sorted order makes package deterministic.
    all_entries = sorted(entries + [manifest_entry], key=lambda x: x["path"])
    created = now()
    header_prefix = [
        "RESOURCEPKG/1",
        "VERSION_MARKER", "RELEASE_MARKER", "CREATED_MARKER",
        f"manifest-sha256: {manifest_sha}", "INDEX_SHA_MARKER",
        "PACKAGE_SIZE_MARKER", f"entry-count: {len(all_entries)}", "BLOBS",
    ]
    body_map = {e["path"]: (manifest_bytes if e["path"] == "manifest.json"
                            else (source_dir / e["path"]).read_bytes()) for e in all_entries}
    data_total = sum(len(body_map[e["path"]]) for e in all_entries)

    def index_text(package_id: str, release_id: str, package_size: int, index_sha: str) -> bytes:
        lines = ["RESOURCEPKG/1", f"package-id: {package_id}", f"version: {version}",
                 f"release-id: {release_id}", f"created-at: {created}",
                 f"manifest-sha256: {manifest_sha}", f"index-sha256: {index_sha}",
                 f"package-size: {package_size:020d}", f"entry-count: {len(all_entries)}"]
        for e in all_entries:
            # The compact transport index intentionally keeps three columns;
            # rich manifest metadata (dimensions and layout dependencies) is in manifest.json.
            lines.append(f'{e["sha256"]} {e["size"]} {e["media_type"]} {e["path"]}')
        lines.append("BLOBS")
        return ("\n".join(lines) + "\n").encode()
    release_id = f"rel-{version.replace('.', '-')}"
    dummy = index_text("0"*64, release_id, 0, "0"*64)
    package_id = hashlib.sha256(dummy).hexdigest()  # stable immutable content identity
    # The fingerprint excludes its own line and the derived package-size line;
    # all fixed-width framing therefore verifies without a self-referential hash.
    provisional = index_text(package_id, release_id, 0, "0"*64)
    def hash_index_without_framing(data: bytes) -> str:
        parts=[]; pos=0
        for prefix in (b"index-sha256:", b"package-size:"):
            line_start=data.find(prefix)
            line_end=data.find(b"\n", line_start)+1
            parts.append((line_start,line_end))
        parts.sort()
        h=hashlib.sha256(); pos=0
        for a,b in parts:
            h.update(data[pos:a]); pos=b
        h.update(data[pos:]); return h.hexdigest()
    index_sha = hash_index_without_framing(provisional)
    package_size = len(provisional) + data_total
    index = index_text(package_id, release_id, package_size, index_sha)
    check = hash_index_without_framing(index)
    if check != index_sha or len(index) != len(provisional):
        raise RuntimeError("internal package framing error")
    state_dir.mkdir(parents=True, exist_ok=True)
    pkg_dir = state_dir / "packages"; pkg_dir.mkdir(parents=True, exist_ok=True)
    tmp = pkg_dir / f".{package_id}.tmp"
    with tmp.open("wb") as f:
        f.write(index)
        for e in all_entries:
            f.write(body_map[e["path"]])
    tmp.replace(pkg_dir / f"{package_id}.rrpkg")
    # Store blobs for per-file dedup/export, even though download serves immutable package.
    for e in all_entries:
        p = state_dir / "blobs" / e["sha256"][:2]
        p.mkdir(parents=True, exist_ok=True)
        b = p / e["sha256"]
        if not b.exists():
            b.write_bytes(body_map[e["path"]])
    con = connect(state_dir)
    try:
        existing = con.execute("SELECT package_id FROM packages WHERE version=?", (version,)).fetchone()
        if existing is not None:
            return existing["package_id"]
        con.execute("INSERT OR IGNORE INTO device_groups(group_id,display_name,created_at) VALUES(?,?,?)",
                    ("factory", "Factory group", created))
        for e in all_entries:
            con.execute("INSERT OR IGNORE INTO files(sha256,media_type,size_bytes,width,height,created_at,ref_count) VALUES(?,?,?,?,?,?,0)",
                        (e["sha256"], e["media_type"], e["size"], e.get("width"), e.get("height"), created))
        if con.execute("SELECT 1 FROM packages WHERE package_id=?", (package_id,)).fetchone() is None:
            con.execute("INSERT INTO packages(package_id,version,package_size,manifest_sha256,created_at) VALUES(?,?,?,?,?)",
                        (package_id, version, package_size, manifest_sha, created))
            con.execute("DELETE FROM package_files WHERE package_id=?", (package_id,))
            for e in all_entries:
                con.execute("INSERT INTO package_files(package_id,sha256,logical_path,media_type,size_bytes,width,height,layout_dependencies,required) VALUES(?,?,?,?,?,?,?,?,?)",
                            (package_id, e["sha256"], e["path"], e["media_type"], e["size"],
                             e.get("width"), e.get("height"), json.dumps(e.get("layout_dependencies", [])), 1 if e.get("required", True) else 0))
        con.commit()
    finally:
        con.close()
    return package_id


def publish(state_dir: Path, group: str, package_id: str, release_id: str | None = None, activate: bool = True) -> str:
    con = connect(state_dir)
    try:
        p = con.execute("SELECT version FROM packages WHERE package_id=?", (package_id,)).fetchone()
        if p is None: raise SystemExit("unknown package")
        if con.execute("SELECT 1 FROM device_groups WHERE group_id=?", (group,)).fetchone() is None:
            con.execute("INSERT INTO device_groups(group_id,display_name,created_at) VALUES(?,?,?)", (group, group, now()))
        rid = release_id or f"grp-{int(time.time())}-{package_id[:8]}"
        if activate:
            con.execute("UPDATE group_releases SET state='rollback', superseded_at=?, retained_until=? WHERE group_id=? AND state='current'",
                        (now(), now(), group))
            # Activating one staged/current release must not activate an unrelated
            # pending row for the same group.
            con.execute("UPDATE OR IGNORE group_releases SET state='current', activated_at=? WHERE group_id=? AND release_id=? AND state='pending'",
                        (now(), group, rid))
            if con.execute("SELECT changes()").fetchone()[0] == 0:
                con.execute("INSERT INTO group_releases(group_id,release_id,package_id,state,created_at,activated_at) VALUES(?,?,?,'current',?,?)",
                            (group, rid, package_id, now(), now()))
        else:
            con.execute("INSERT INTO group_releases(group_id,release_id,package_id,state,created_at) VALUES(?,?,?,'pending',?)",
                        (group, rid, package_id, now()))
        con.commit(); return rid
    finally: con.close()


def rollback(state_dir: Path, group: str) -> str:
    con = connect(state_dir)
    try:
        r = con.execute("SELECT * FROM group_releases WHERE group_id=? AND state='rollback' ORDER BY superseded_at DESC, release_id DESC LIMIT 1", (group,)).fetchone()
        if r is None: raise SystemExit("no retained rollback release")
        con.execute("UPDATE group_releases SET state='rollback', superseded_at=? WHERE group_id=? AND state='current'", (now(), group))
        con.execute("UPDATE group_releases SET state='current', activated_at=?, superseded_at=NULL, retained_until=NULL WHERE group_id=? AND release_id=?",
                    (now(), group, r["release_id"]))
        con.commit(); return r["release_id"]
    finally: con.close()


def gc(state_dir: Path, retain_seconds: int = 7 * 86400) -> dict:
    cutoff = datetime.now(timezone.utc).timestamp() - retain_seconds
    con = connect(state_dir)
    removed_files = removed_packages = removed_bytes = 0
    try:
        # Expire only timed-out rollback retention. Current display and pending
        # staging have no TTL; download/access time is deliberately not used.
        for r in con.execute("SELECT rowid,superseded_at FROM group_releases WHERE state='rollback'").fetchall():
            if r["superseded_at"]:
                try:
                    if datetime.fromisoformat(r["superseded_at"]).timestamp() < cutoff:
                        con.execute("DELETE FROM group_releases WHERE rowid=?", (r["rowid"],))
                except ValueError:
                    pass
        con.commit()
        active = {r["package_id"] for r in con.execute(
            "SELECT DISTINCT package_id FROM group_releases WHERE state IN ('current','pending','rollback')")}
        for r in con.execute("SELECT package_id FROM packages").fetchall():
            if r["package_id"] not in active:
                f = state_dir / "packages" / f"{r['package_id']}.rrpkg"
                if f.exists():
                    f.unlink(); removed_packages += 1
                con.execute("DELETE FROM packages WHERE package_id=?", (r["package_id"],))
        con.commit()
        # package_files triggers synchronize files.ref_count after package deletion.
        # A blob is physical garbage only when no immutable package member remains.
        for r in con.execute("SELECT sha256,size_bytes,ref_count FROM files WHERE ref_count=0").fetchall():
            p = state_dir / "blobs" / r["sha256"][:2] / r["sha256"]
            if p.exists():
                p.unlink(); removed_files += 1; removed_bytes += r["size_bytes"]
            con.execute("DELETE FROM files WHERE sha256=?", (r["sha256"],))
        con.commit()
        return {"removed_packages": removed_packages, "removed_files": removed_files,
                "removed_bytes": removed_bytes,
                "current_pending_rollback_packages": sorted(active)}
    finally:
        con.close()


def diagnostics(state_dir: Path) -> list[dict]:
    con = connect(state_dir); out=[]
    try:
        for r in con.execute("""SELECT pf.logical_path,pf.sha256,pf.media_type,pf.size_bytes,pf.width,pf.height,pf.layout_dependencies,pf.required,
            p.version,p.package_id,gr.group_id,gr.state FROM package_files pf JOIN packages p ON p.package_id=pf.package_id
            JOIN group_releases gr ON gr.package_id=p.package_id ORDER BY gr.group_id,gr.created_at,p.version,pf.logical_path"""):
            path=state_dir/"blobs"/r["sha256"][:2]/r["sha256"]
            reasons=[]
            if not path.is_file(): reasons.append("blob file is absent on server")
            else:
                if path.stat().st_size != r["size_bytes"]: reasons.append("file size differs from manifest")
                if sha256_file(path) != r["sha256"]: reasons.append("content fingerprint mismatch")
            if not r["media_type"]: reasons.append("media type missing")
            deps=json.loads(r["layout_dependencies"] or "[]")
            if not isinstance(deps,list): reasons.append("layout dependencies must be an array")
            if reasons:
                out.append({"group_id":r["group_id"],"state":r["state"],"version":r["version"],
                            "path":r["logical_path"],"expected_sha256":r["sha256"],"reasons":reasons})
        for r in con.execute("SELECT * FROM missing_reports ORDER BY id DESC LIMIT 50"):
            d=dict(r); d["source"]="device report"; out.append(d)
        return out
    finally: con.close()


class Handler(http.server.BaseHTTPRequestHandler):
    server_version = "ResourceServer/1.0"
    def log_message(self, fmt, *args): pass
    @property
    def state(self) -> Path: return Path(self.server.state_dir)
    def send_json(self, code, obj):
        data=json.dumps(obj,ensure_ascii=False).encode()
        self.send_response(code); self.send_header("Content-Type","application/json; charset=utf-8")
        self.send_header("Content-Length",str(len(data))); self.end_headers(); self.wfile.write(data)
    def read_json(self):
        n=int(self.headers.get("Content-Length","0") or 0)
        if n<=0 or n>65536: return {}
        try: return json.loads(self.rfile.read(n).decode())
        except Exception: return {}
    def con(self): return connect(self.state)
    def do_GET(self):
        u=urllib.parse.urlparse(self.path); q=urllib.parse.parse_qs(u.query)
        if u.path=="/":
            return self.static("index.html","text/html; charset=utf-8")
        if u.path.startswith("/static/"):
            name=u.path[len("/static/"):]
            types={"index.html":"text/html; charset=utf-8","app.js":"application/javascript; charset=utf-8","styles.css":"text/css; charset=utf-8"}
            if safe_relative(name) and name in types: return self.static(name,types[name])
        if u.path=="/api/packages":
            with self.con() as c:
                return self.send_json(200,[{"package_id":r["package_id"],"version":r["version"],"size":r["package_size"]} for r in c.execute("SELECT * FROM packages ORDER BY created_at")])
        if u.path=="/api/releases":
            with self.con() as c:
                return self.send_json(200,[dict(r) for r in c.execute("SELECT * FROM group_releases ORDER BY created_at DESC")])
        if u.path=="/api/inventory":
            with self.con() as c:
                rows=c.execute("""SELECT pf.logical_path,pf.media_type,pf.size_bytes,pf.width,pf.height,
                                 pf.layout_dependencies,pf.required,p.version,p.package_id,
                                 GROUP_CONCAT(gr.group_id||':'||gr.state,', ') AS releases
                                 FROM package_files pf JOIN packages p ON p.package_id=pf.package_id
                                 LEFT JOIN group_releases gr ON gr.package_id=p.package_id
                                 GROUP BY pf.package_id,pf.logical_path
                                 ORDER BY pf.logical_path,p.version""").fetchall()
                return self.send_json(200,[dict(r) for r in rows])
        if u.path=="/api/groups":
            with self.con() as c: return self.send_json(200,[dict(r) for r in c.execute("SELECT * FROM device_groups")])
        if u.path=="/api/diagnostics": return self.send_json(200,diagnostics(self.state))
        if u.path=="/api/devices/assignment":
            device=self.headers.get("X-Device-ID","")
            if not device: return self.send_json(400,{"error":"missing X-Device-ID"})
            with self.con() as c:
                d=c.execute("SELECT * FROM devices WHERE device_id=?",(device,)).fetchone()
                if d is None or not d["group_id"]: return self.send_json(404,{"error":"device not enrolled"})
                gr=c.execute("SELECT * FROM group_releases WHERE group_id=? AND state='current' ORDER BY activated_at DESC LIMIT 1",(d["group_id"],)).fetchone()
                if gr is None: return self.send_json(404,{"error":"no current release"})
                p=c.execute("SELECT * FROM packages WHERE package_id=?",(gr["package_id"],)).fetchone()
                c.execute("UPDATE devices SET last_seen_at=? WHERE device_id=?",(now(),device));c.commit()
                return self.send_json(200,{"group_id":d["group_id"],"release_id":gr["release_id"],
                    "package_id":p["package_id"],"version":p["version"],
                    "index_url":f"/api/groups/{d['group_id']}/releases/{gr['release_id']}/index"})
        parts=u.path.strip("/").split("/")
        if len(parts)==6 and parts[0:2]==["api","groups"] and parts[3]=="releases":
            group,release,kind=parts[2],parts[4],parts[5]
            return self.serve_release(group,release,kind)
        return self.send_json(404,{"error":"not found"})
    def do_POST(self):
        u=urllib.parse.urlparse(self.path); body=self.read_json()
        if u.path=="/api/devices/enroll":
            device=body.get("device_id",""); group=body.get("group_id","")
            if len(device)!=64 or not all(x in "0123456789abcdef" for x in device) or not group:
                return self.send_json(400,{"error":"invalid device or group"})
            with self.con() as c:
                if c.execute("SELECT 1 FROM device_groups WHERE group_id=?",(group,)).fetchone() is None:
                    return self.send_json(403,{"error":"unknown group"})
                d=c.execute("SELECT * FROM devices WHERE device_id=?",(device,)).fetchone()
                other=c.execute("SELECT device_id FROM devices WHERE group_id=? AND device_id<>? LIMIT 1",(group,device)).fetchone()
                if other: return self.send_json(409,{"error":"group already assigned to another device"})
                if d is None: c.execute("INSERT INTO devices(device_id,group_id,display_name,enrolled_at,last_seen_at) VALUES(?,?,?,?,?)",(device,group,device[:8],now(),now()))
                elif d["group_id"] != group: return self.send_json(403,{"error":"device cannot claim another group's resources"})
                c.execute("INSERT INTO device_events(device_id,group_id,release_id,package_id,status,created_at) VALUES(?,?,?,?,?,?)",(device,group,"","","enrolled",now()))
                c.commit(); return self.send_json(200,{"ok":True})
        if u.path=="/api/devices/report":
            required=["device_id","group_id","release_id","package_id","status"]
            if any(not body.get(k) for k in required): return self.send_json(400,{"error":"incomplete report"})
            with self.con() as c:
                d=c.execute("SELECT * FROM devices WHERE device_id=?",(body["device_id"],)).fetchone()
                if d is None or d["group_id"]!=body["group_id"]: return self.send_json(403,{"error":"cross group report"})
                c.execute("INSERT INTO device_events(device_id,group_id,release_id,package_id,status,message,created_at) VALUES(?,?,?,?,?,?,?)",
                          (body["device_id"],body["group_id"],body["release_id"],body["package_id"],body["status"],body.get("message"),now()))
                c.commit(); return self.send_json(200,{"ok":True})
        if u.path=="/api/missing":
            with self.con() as c:
                c.execute("INSERT INTO missing_reports(device_id,logical_path,expected_sha256,reason,created_at) VALUES(?,?,?,?,?)",
                          (body.get("device_id"),body.get("logical_path"),body.get("expected_sha256"),body.get("reason","missing"),now()))
                c.commit(); return self.send_json(200,{"ok":True})
        return self.send_json(404,{"error":"not found"})
    def static(self,name,ctype):
        p=(ROOT/"server"/"web"/name).resolve()
        root=(ROOT/"server"/"web").resolve()
        try: p.relative_to(root)
        except ValueError: return self.send_json(403,{"error":"path escape"})
        if not p.is_file(): return self.send_json(404,{"error":"missing web asset"})
        data=p.read_bytes(); self.send_response(200); self.send_header("Content-Type",ctype)
        self.send_header("Content-Length",str(len(data))); self.end_headers(); self.wfile.write(data)
    def serve_release(self,group,release,kind):
        if kind not in ("index","package"): return self.send_json(404,{"error":"not found"})
        device=self.headers.get("X-Device-ID","")
        with self.con() as c:
            d=c.execute("SELECT * FROM devices WHERE device_id=?",(device,)).fetchone()
            if d is None or d["group_id"]!=group: return self.send_json(403,{"error":"this resource belongs to another device group"})
            gr=c.execute("SELECT * FROM group_releases WHERE group_id=? AND release_id=? AND state IN ('current','rollback','pending')",(group,release)).fetchone()
            if gr is None: return self.send_json(404,{"error":"release not found"})
            p=c.execute("SELECT * FROM packages WHERE package_id=?",(gr["package_id"],)).fetchone()
            f=self.state/"packages"/f"{p['package_id']}.rrpkg"
            if not f.is_file(): return self.send_json(410,{"error":"immutable package missing on server"})
            data=f.read_bytes()
            if kind=="index":
                end=data.index(b"\nBLOBS\n")+len(b"\nBLOBS\n"); data=data[:end]
            self.send_response(200); self.send_header("Content-Type","application/octet-stream")
            self.send_header("Content-Length",str(len(data))); self.end_headers(); self.wfile.write(data)


def init_demo(state_dir: Path):
    materialize_demo_sources()
    p1=build_package(state_dir,ROOT/"resources"/"source-v1","1.0.0")
    p2=build_package(state_dir,ROOT/"resources"/"source-v2","2.0.0")
    con=connect(state_dir)
    try:
        if con.execute("SELECT COUNT(*) c FROM device_groups").fetchone()["c"]==0:
            con.execute("INSERT INTO device_groups(group_id,display_name,created_at) VALUES(?,?,?)",("factory","Factory group",now()))
            con.execute("INSERT INTO device_groups(group_id,display_name,created_at) VALUES(?,?,?)",("kiosk","Kiosk group",now()))
        if con.execute("SELECT COUNT(*) c FROM group_releases WHERE group_id='factory'").fetchone()["c"]==0:
            publish(state_dir,"factory",p1,"factory-v1",True)
            publish(state_dir,"factory",p2,"factory-v2-pending",False)
        con.commit()
    finally: con.close()


def main(argv=None):
    ap=argparse.ArgumentParser()
    ap.add_argument("--state",default=str(DEFAULT_STATE))
    sub=ap.add_subparsers(dest="cmd",required=True)
    for name in ("init-demo","serve","build","publish","rollback","gc","diagnostics"):
        s=sub.add_parser(name)
        if name=="serve": s.add_argument("--host",default="127.0.0.1"); s.add_argument("--port",type=int,default=8088)
        if name=="build": s.add_argument("source"); s.add_argument("version")
        if name=="publish": s.add_argument("group"); s.add_argument("package_id"); s.add_argument("--release-id"); s.add_argument("--pending",action="store_true")
        if name=="rollback": s.add_argument("group")
    args=ap.parse_args(argv); state=Path(args.state)
    if args.cmd=="init-demo": init_demo(state); print(json.dumps({"state":str(state)}))
    elif args.cmd=="build": print(build_package(state,Path(args.source),args.version))
    elif args.cmd=="publish": print(publish(state,args.group,args.package_id,args.release_id,not args.pending))
    elif args.cmd=="rollback": print(rollback(state,args.group))
    elif args.cmd=="gc": print(json.dumps(gc(state),ensure_ascii=False,indent=2))
    elif args.cmd=="diagnostics": print(json.dumps(diagnostics(state),ensure_ascii=False,indent=2))
    elif args.cmd=="serve":
        init_demo(state)
        httpd=http.server.ThreadingHTTPServer((args.host,args.port),Handler)
        httpd.state_dir=str(state)
        print(f"resource server listening on http://{args.host}:{args.port}")
        httpd.serve_forever()

if __name__ == "__main__":
    main()
