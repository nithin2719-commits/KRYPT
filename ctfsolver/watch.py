"""Real-time WATCH / auto-hunt — catch the flag the moment the file lands.

Point KRYPT at one or more directories (your ~/Downloads, a shared CTF drop, the
GUI uploads folder) and every new or modified file is swept for flags the instant
it appears — plaintext *and* base64/hex-encoded — with an optional full-pipeline
deep hunt per file. This is the "start hunting as soon as the challenge is
dropped/pasted" mode.

Pure stdlib: a debounced polling watcher, no watchdog/inotify dependency. Files
are de-duplicated by content hash, and writes are allowed to settle (size stable
across two polls) before a file is scanned, so half-written downloads never
produce a torn read.

Authorized CTF use only.
"""
from __future__ import annotations

import datetime as dt
import hashlib
import os
import sys
import threading
import time

from .flags import instant_scan

_COLOR = sys.stdout.isatty() and os.environ.get("NO_COLOR") is None
_C = {"g": "\033[92m", "y": "\033[93m", "c": "\033[96m", "d": "\033[90m",
      "b": "\033[1m", "x": "\033[0m"} if _COLOR else dict.fromkeys("gycdbx", "")

# files we never bother scanning (our own outputs, VCS, editor junk)
_SKIP_DIRS = {".git", "__pycache__", ".pytest_cache", "node_modules",
              "binwalk_extract"}
_SKIP_EXT = {".part", ".crdownload", ".tmp", ".swp", ".swx"}


def _sha1(path: str, max_bytes: int = 64 * 1024 * 1024) -> str | None:
    h = hashlib.sha1()
    try:
        with open(path, "rb") as fh:
            read = 0
            for chunk in iter(lambda: fh.read(65536), b""):
                h.update(chunk)
                read += len(chunk)
                if read >= max_bytes:
                    break
    except OSError:
        return None
    return h.hexdigest()


class FlagWatcher:
    """Watch directories and auto-hunt flags in new/changed files.

    on_find(record) is called for every file that yields at least one new flag;
    record = {time, path, flags:[{flag,kind,confidence,...}], deep:bool}.
    """

    def __init__(self, dirs, deep: bool = False, event: str = "",
                 interval: float = 0.8, recursive: bool = True,
                 on_find=None, logdir: str | None = None,
                 max_bytes: int = 64 * 1024 * 1024, max_finds: int = 500):
        self.dirs = [os.path.abspath(os.path.expanduser(d)) for d in dirs]
        self.deep = deep
        self.event = (event or "").strip()
        self.interval = max(0.15, float(interval))
        self.recursive = recursive
        self.on_find = on_find
        self.max_bytes = max_bytes
        self.max_finds = max_finds

        self._seen: set[str] = set()            # content hashes already scanned
        self._flagged: set[str] = set()         # "sha1\tflag" already reported
        self._pending: dict[str, tuple] = {}     # path -> (size, mtime) last poll
        self._stop = threading.Event()
        self._lock = threading.Lock()
        self.finds: list[dict] = []             # ring buffer of discoveries
        self.scanned = 0
        self.started = dt.datetime.now().isoformat(timespec="seconds")

        self.logdir = os.path.abspath(logdir) if logdir else None
        self.logpath = os.path.join(self.logdir, "found_flags.log") if self.logdir else None
        if self.logdir:
            os.makedirs(self.logdir, exist_ok=True)

    # ---- scanning -------------------------------------------------------
    def _is_own_output(self, path: str) -> bool:
        """Never scan our own log/output — otherwise writing a found flag to the
        log would be re-detected as a new flag (a feedback loop) when the log
        lives inside a watched directory."""
        if self.logdir and os.path.abspath(path).startswith(self.logdir + os.sep):
            return True
        return os.path.basename(path) == "found_flags.log"

    def _candidates(self):
        for base in self.dirs:
            if not os.path.isdir(base):
                continue
            if self.recursive:
                for root, dirs, files in os.walk(base):
                    dirs[:] = [d for d in dirs if d not in _SKIP_DIRS]
                    for fn in files:
                        p = os.path.join(root, fn)
                        if not self._is_own_output(p):
                            yield p
            else:
                for fn in os.listdir(base):
                    p = os.path.join(base, fn)
                    if os.path.isfile(p) and not self._is_own_output(p):
                        yield p

    def _scan_one(self, path: str, sig: str):
        flags = instant_scan(path, self.max_bytes)
        deep_steps = None
        if self.deep:
            try:
                from .__main__ import run_pipeline
                res = run_pipeline(path)
                deep_steps = res.get("steps")
                merged = {f["flag"]: f for f in flags}
                for f in res.get("flags", []):
                    cur = merged.get(f["flag"])
                    if not cur or f["confidence"] > cur["confidence"]:
                        merged[f["flag"]] = f
                flags = sorted(merged.values(), key=lambda d: -d["confidence"])
            except Exception as e:  # deep hunt must never kill the watch loop
                deep_steps = [{"step": "deep-error", "summary": str(e)}]

        fresh = [f for f in flags if f"{sig}\t{f['flag']}" not in self._flagged]
        if not fresh:
            return
        for f in fresh:
            self._flagged.add(f"{sig}\t{f['flag']}")
        rec = {"time": dt.datetime.now().isoformat(timespec="seconds"),
               "path": path, "flags": fresh, "deep": bool(self.deep)}
        with self._lock:
            self.finds.append(rec)
            del self.finds[:-self.max_finds]
        self._log(rec)
        self._save_event(rec, path, deep_steps)
        if self.on_find:
            try:
                self.on_find(rec)
            except Exception:
                pass

    def _log(self, rec: dict):
        if not self.logpath:
            return
        try:
            with open(self.logpath, "a") as fh:
                for f in rec["flags"]:
                    fh.write(f"{rec['time']}\t{rec['path']}\t{f['confidence']}\t"
                             f"{f['kind']}\t{f['flag']}\n")
        except OSError:
            pass

    def _save_event(self, rec: dict, path: str, deep_steps):
        if not self.event or not rec["flags"]:
            return
        try:
            from . import vault
            res = {"target": {"kind": "watch", "raw": path, "subkind": "", "mime": ""},
                   "workdir": self.logdir or "", "flags": rec["flags"],
                   "steps": deep_steps or [{
                       "step": "watch", "summary": f"auto-captured from {path}",
                       "output": "", "flags": rec["flags"]}]}
            vault.add_solve(self.event, res, rec["flags"][0]["flag"], "watch")
        except Exception:
            pass

    def poll_once(self):
        """One sweep: pick up files whose size has settled since last poll, scan
        the new/changed ones (by content hash), and remember current sizes."""
        current = {}
        for path in self._candidates():
            ext = os.path.splitext(path)[1].lower()
            if ext in _SKIP_EXT:
                continue
            try:
                st = os.stat(path)
            except OSError:
                continue
            if st.st_size == 0:
                continue
            key = (st.st_size, int(st.st_mtime))
            current[path] = key
            prev = self._pending.get(path)
            if prev != key:
                continue  # still changing — wait for it to settle
            sig = _sha1(path, self.max_bytes)
            if not sig or sig in self._seen:
                continue
            self._seen.add(sig)
            self.scanned += 1
            self._scan_one(path, sig)
        self._pending = current

    def run(self):
        while not self._stop.is_set():
            try:
                self.poll_once()
            except Exception:
                pass
            self._stop.wait(self.interval)

    def start_thread(self) -> threading.Thread:
        t = threading.Thread(target=self.run, name="krypt-watch", daemon=True)
        t.start()
        return t

    def stop(self):
        self._stop.set()

    def status(self) -> dict:
        with self._lock:
            finds = list(self.finds)
        return {"running": not self._stop.is_set(), "dirs": self.dirs,
                "deep": self.deep, "event": self.event, "interval": self.interval,
                "scanned": self.scanned, "started": self.started,
                "count": sum(len(f["flags"]) for f in finds),
                "finds": finds[-60:]}


def _print_find(rec: dict):
    ts = rec["time"].split("T")[-1]
    tag = "DEEP" if rec["deep"] else "FAST"
    print(f"\n{_C['g']}{_C['b']}🚩 FLAG{_C['x']} {_C['d']}{ts} · {tag} · "
          f"{rec['path']}{_C['x']}")
    for f in rec["flags"]:
        enc = f" {_C['y']}[{f['kind']}]{_C['x']}" if f.get("encoded") else \
              f" {_C['d']}({f['kind']}){_C['x']}"
        print(f"  {_C['c']}{_C['b']}{f['flag']}{_C['x']}"
              f"  {_C['d']}conf {f['confidence']}{_C['x']}{enc}")
    sys.stdout.flush()   # appear live even when piped/redirected (GUI log, tee)


def watch_cli(dirs, deep=False, event="", interval=0.8, recursive=True) -> int:
    """Blocking CLI watch loop with live colored output. Ctrl-C to stop."""
    real = [d for d in dirs if os.path.isdir(os.path.expanduser(d))]
    if not real:
        print(f"{_C['y']}no valid directory to watch:{_C['x']} {', '.join(dirs)}",
              file=sys.stderr)
        return 2
    logdir = os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        "workspace", "watch")
    w = FlagWatcher(real, deep=deep, event=event, interval=interval,
                    recursive=recursive, on_find=_print_find, logdir=logdir)
    mode = "DEEP (full pipeline)" if deep else "FAST (instant sweep)"
    print(f"{_C['b']}KRYPT WATCH{_C['x']} · {mode} · every {w.interval:g}s")
    for d in w.dirs:
        print(f"  {_C['d']}watching{_C['x']} {d}")
    if event:
        print(f"  {_C['d']}auto-save flags to event{_C['x']} {_C['c']}{event}{_C['x']}")
    print(f"  {_C['d']}log{_C['x']} {w.logpath}")
    print(f"{_C['d']}(Ctrl-C to stop){_C['x']}\n")
    try:
        w.run()
    except KeyboardInterrupt:
        n = sum(len(f["flags"]) for f in w.finds)
        print(f"\n{_C['b']}stopped{_C['x']} · {w.scanned} file(s) scanned · "
              f"{n} flag(s) captured")
    return 0
