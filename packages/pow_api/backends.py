"""Where a validated record goes.

Two backends. `local` writes commits to a git repository on disk, so the whole
loop runs offline with no GitHub account and no token — that is the development
story and it needs no container. `github` writes through the contents API, because
a Render web service has ephemeral disk and holding a working tree there is
fragile.

Neither backend decides anything. By the time a record reaches here it has already
passed the same validation CI will run, and it carries a signature the backend
cannot forge.
"""
from __future__ import annotations

import base64
import json
import os
import subprocess
import time
from pathlib import Path
from typing import Dict, List, Optional, Protocol

import httpx


class Backend(Protocol):
    def read_dir(self, name: str) -> List[dict]: ...
    def head(self) -> str: ...
    def put(self, path: str, content: bytes, message: str) -> str: ...


class LocalBackend:
    def __init__(self, root: Path) -> None:
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True)
        if not (self.root / ".git").exists():
            self._git("init", "-q", "-b", "main")
            self._git("config", "user.email", "pow@localhost")
            self._git("config", "user.name", "pow")
        for d in ("claims", "verdicts", "seals", "handouts", "agents", "observatory"):
            (self.root / d).mkdir(exist_ok=True)

    def _git(self, *args: str) -> str:
        return subprocess.run(
            ["git", *args], cwd=self.root, check=True,
            capture_output=True, text=True,
        ).stdout.strip()

    def read_dir(self, name: str) -> List[dict]:
        d = self.root / name
        if not d.is_dir():
            return []
        return [json.loads(f.read_text("utf-8")) for f in sorted(d.glob("*.json"))]

    def head(self) -> str:
        try:
            return self._git("rev-parse", "HEAD")
        except subprocess.CalledProcessError:
            return "0" * 40

    def put(self, path: str, content: bytes, message: str) -> str:
        target = self.root / path
        target.parent.mkdir(parents=True, exist_ok=True)
        if target.exists():
            raise FileExistsError(path)
        target.write_bytes(content)
        self._git("add", path)
        self._git("commit", "-q", "-m", message)
        return self.head()


class GitHubBackend:
    def __init__(self, repo: str, token: str, branch: str = "main") -> None:
        self.repo, self.branch = repo, branch
        self.client = httpx.Client(
            base_url="https://api.github.com",
            headers={
                "Authorization": f"Bearer {token}",
                "Accept": "application/vnd.github+json",
                "X-GitHub-Api-Version": "2022-11-28",
            },
            timeout=20.0,
        )

    def read_dir(self, name: str) -> List[dict]:
        r = self.client.get(f"/repos/{self.repo}/contents/{name}", params={"ref": self.branch})
        if r.status_code == 404:
            return []
        r.raise_for_status()
        out = []
        for entry in r.json():
            if entry["name"].endswith(".json"):
                blob = self.client.get(entry["download_url"])
                blob.raise_for_status()
                out.append(blob.json())
        return out

    def head(self) -> str:
        r = self.client.get(f"/repos/{self.repo}/commits/{self.branch}")
        r.raise_for_status()
        return r.json()["sha"]

    def put(self, path: str, content: bytes, message: str) -> str:
        existing = self.client.get(
            f"/repos/{self.repo}/contents/{path}", params={"ref": self.branch}
        )
        if existing.status_code == 200:
            raise FileExistsError(path)
        r = self.client.put(
            f"/repos/{self.repo}/contents/{path}",
            json={
                "message": message,
                "content": base64.b64encode(content).decode("ascii"),
                "branch": self.branch,
            },
        )
        r.raise_for_status()
        return r.json()["commit"]["sha"]


def from_env() -> Backend:
    kind = os.environ.get("LOG_BACKEND", "local")
    if kind == "github":
        repo, token = os.environ["LOG_REPO"], os.environ["GITHUB_TOKEN"]
        return GitHubBackend(repo, token, os.environ.get("LOG_BRANCH", "main"))
    return LocalBackend(Path(os.environ.get("LOG_PATH", "./tmp/pow-log")))


def read_plane_from_env(log: Backend):
    """The read model, if one is published. Local development has none and does
    not need one: a filesystem read costs nothing."""
    base = os.environ.get("READ_PLANE", "").strip()
    return ReadPlane(base, log) if base else None


class ReadPlane:
    """Reads from the published site instead of from the log.

    The log is the write model and the generated site is the read model — the
    split the architecture already implied, made explicit. Reading records back
    out of GitHub cost one HTTP request per record, so a single GET /v0/claims at
    a few hundred records could exhaust an hour's rate limit. The generator
    already visits every record; it now writes them out in one file per kind, and
    this reads that.

    It is a cache, and it is never authoritative. Where this and the log
    disagree, this is wrong — so anything that must be correct rather than fast
    keeps reading the log directly, and /v0/health publishes how far behind this
    is rather than pretending it is not.
    """

    TTL = 20.0

    def __init__(self, base: str, fallback: Backend) -> None:
        self.base = base.rstrip("/")
        self.fallback = fallback
        self.client = httpx.Client(timeout=10.0, follow_redirects=True)
        self._cache: Dict[str, tuple] = {}
        self.head = ""
        self.generated_from = ""
        self.degraded = ""

    def read_dir(self, name: str) -> List[dict]:
        hit = self._cache.get(name)
        if hit and time.monotonic() - hit[0] < self.TTL:
            return hit[1]
        try:
            r = self.client.get(f"{self.base}/records/{name}.json")
            r.raise_for_status()
            doc = r.json()
            rows = doc.get(name, [])
            self.head = doc.get("head_commit", "")
            self.generated_from = doc.get("generated_from", "")
            self.degraded = ""
        except (httpx.HTTPError, ValueError) as exc:
            # A broken build must not freeze reads at whatever was last good.
            # Fall through to the log and say so, loudly, in health.
            self.degraded = f"{type(exc).__name__} reading the read plane"
            return self.fallback.read_dir(name)
        self._cache[name] = (time.monotonic(), rows)
        return rows

    def put(self, path: str, content: bytes, message: str) -> str:
        raise RuntimeError("the read plane is read-only; writes go to the log")
