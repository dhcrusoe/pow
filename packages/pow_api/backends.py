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
from pathlib import Path
from typing import List, Optional, Protocol

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
