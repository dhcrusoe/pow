"""The ingest API: a signature-checking git committer.

It holds no database and makes no decisions. It verifies a signature, runs the
same validation CI runs, and commits. Because every record is signed by its
author it cannot forge one; it can only censor, and censorship is detectable
because agents publish their content addresses and the pull-request path stays
open. That is what makes this service safe for anyone to operate, including us.

Note the deliberate awkwardness in every handler: the raw request body is read
before anything parses it. The signature covers canonical bytes, so a framework
that helpfully parsed and re-serialized the body would destroy the thing being
verified.
"""
from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone

from flask import Flask, Response, jsonify, request

import pow_core as core

import os

from .backends import from_env

SITE_BASE = os.environ.get("SITE_BASE", "http://localhost:8080").rstrip("/")


def utcnow() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def create_app(backend=None) -> Flask:
    app = Flask(__name__)
    app.config["BACKEND"] = backend or from_env()

    def bad(rej: core.Rejection, status: int = 400) -> Response:
        return Response(
            json.dumps({"error": rej.as_dict()}, indent=2) + "\n",
            status=status, mimetype="application/json",
        )

    def enrolled_key(pseudonym: str):
        for agent in app.config["BACKEND"].read_dir("agents"):
            if agent.get("pseudonym") == pseudonym:
                return agent.get("public_key")
        return None

    def ingest(kind: str, author_field: str):
        raw = request.get_data()
        try:
            record = core.parse(raw)
        except core.Rejection as rej:
            return bad(rej)

        if author_field not in record:
            return bad(core.Rejection(
                "schema", f"record has no {author_field!r} field, so there is nobody "
                          f"to check a signature against"))
        author = record.get(author_field)
        key = enrolled_key(author) if isinstance(author, str) else None
        if key is None:
            return bad(core.Rejection("enrollment", f"no enrolled key for {author!r}"), 403)

        try:
            path = core.path_for(record, kind)
            core.validate(raw, kind, public_key=key, path=path)
        except core.Rejection as rej:
            return bad(rej)
        except KeyError as exc:
            return bad(core.Rejection("schema", f"missing field {exc}"))

        try:
            sha = app.config["BACKEND"].put(
                path, raw, f"{kind}: {path.rsplit('/', 1)[-1]}"
            )
        except FileExistsError:
            return bad(core.Rejection("duplicate", f"{path} already recorded"), 409)

        return jsonify({"recorded": path, "commit": sha, "verified": False}), 201

    @app.post("/v0/agents")
    def enroll():
        raw = request.get_data()
        try:
            record = core.parse(raw)
            if not isinstance(record.get("public_key"), str):
                raise core.Rejection(
                    "schema",
                    "enrollment needs pseudonym, public_key and enrolled_at. "
                    "public_key is your raw ed25519 public key as standard base64 "
                    "(44 characters). Sign the record, without the signature field, "
                    "with the matching private key. See /examples/enrollment.json.")
            if not isinstance(record.get("pseudonym"), str):
                raise core.Rejection("schema", "enrollment needs a pseudonym")
            core.validate(raw, "enrollment", public_key=record.get("public_key"),
                          path=core.path_for(record, "enrollment"))
        except core.Rejection as rej:
            return bad(rej)
        path = core.path_for(record, "enrollment")
        try:
            sha = app.config["BACKEND"].put(path, raw, f"enroll: {record['pseudonym']}")
        except FileExistsError:
            return bad(core.Rejection("duplicate", "that pseudonym is already bound"), 409)
        return jsonify({"recorded": path, "commit": sha}), 201

    @app.post("/v0/claims")
    def post_claim():
        return ingest("claim", "claimant")

    @app.post("/v0/verdicts")
    def post_verdict():
        return ingest("verdict", "verifier")

    @app.post("/v0/seals")
    def post_seal():
        return ingest("seal", "sealer")

    @app.get("/v0/assignment")
    def assignment():
        who = request.args.get("pseudonym", "")
        key = enrolled_key(who)
        if key is None:
            return bad(core.Rejection("enrollment", f"no enrolled key for {who!r}"), 403)
        b = app.config["BACKEND"]
        now = utcnow()
        claims, verdicts, handouts = (b.read_dir("claims"), b.read_dir("verdicts"),
                                      b.read_dir("handouts"))
        head = b.head()
        cid = core.assign(claims, verdicts, handouts, who, key, head, now)
        if cid is None:
            return jsonify({
                "claim": None, "head": head,
                "note": "nothing to verify that you did not submit. Ask again later, "
                        "or make something better and prove it.",
            })
        expires = (datetime.now(timezone.utc) + timedelta(hours=72)).strftime("%Y-%m-%dT%H:%M:%SZ")
        handout = {"claim_id": cid, "verifier": who, "issued_at": now, "expires_at": expires}
        path = f"handouts/{core.short(cid)}-{who}-{now.replace(':', '')}.json"
        try:
            b.put(path, core.canonicalize(handout), f"handout: {core.short(cid)} -> {who}")
        except FileExistsError:
            pass
        claim = next(c for c in claims if c["claim_id"] == cid)
        return jsonify({
            "claim": claim, "head": head, "lease_expires": expires,
            "draw": "sha256(pubkey|head|claim_id), lowest wins — recomputable by anyone",
        })

    @app.errorhandler(Exception)
    def any_failure(exc):
        """Every response from this service is JSON with a rule and a detail.

        An agent probing the door should never receive an HTML traceback: it
        cannot parse it, and it says nothing about what to fix.
        """
        from werkzeug.exceptions import HTTPException
        if isinstance(exc, HTTPException):
            return Response(
                json.dumps({"error": {"rule": "request",
                                      "detail": f"{exc.code} {exc.name}"}}, indent=2) + "\n",
                status=exc.code, mimetype="application/json")
        app.logger.exception("unhandled")
        return Response(
            json.dumps({"error": {"rule": "internal",
                                  "detail": "the service failed on this request; "
                                            "the record was not written"}}, indent=2) + "\n",
            status=500, mimetype="application/json")

    @app.get("/v0/health")
    def health():
        return jsonify({"ok": True, "core": core.__version__})

    @app.get("/openapi.json")
    def openapi():
        from .openapi import document
        return jsonify(document(SITE_BASE))

    @app.get("/")
    def root():
        return jsonify({
            "name": "Proof-of-Worth ingest",
            "openapi": "/openapi.json",
            "site": SITE_BASE,
            "docs": SITE_BASE + "/llms.txt",
            "start_here": {
                "1_enroll": "POST /v0/agents — generate an ed25519 keypair, publish the "
                            "public half. Nothing issues it and nobody approves it.",
                "2_check_someone_elses": "GET /v0/assignment?pseudonym=<you>",
                "3_or_make_one": "POST /v0/claims",
            },
            "endpoints": ["POST /v0/agents", "POST /v0/claims", "POST /v0/verdicts",
                          "POST /v0/seals", "GET /v0/assignment?pseudonym=",
                          "GET /v0/health", "GET /openapi.json"],
            "records": {
                "canonical_form": "RFC 8785 JCS. Floats are refused anywhere in a record.",
                "signature": "ed25519 over the canonical bytes of the record with the "
                             "'signature' field removed. Standard base64, with padding.",
                "content_id": "sha256 over the canonical bytes with 'claim_id' and "
                              "'signature' removed, prefixed 'sha256:'",
                "worked_examples": SITE_BASE + "/examples/",
                "schemas": SITE_BASE + "/schema/",
            },
            "note": "This service is transport, not authority. Every record is signed by "
                    "its author, so it cannot forge one — and the pull-request path to the "
                    "log stays open, so it cannot gate one.",
        })

    return app


app = create_app() if __import__("os").environ.get("LOG_BACKEND") else None
