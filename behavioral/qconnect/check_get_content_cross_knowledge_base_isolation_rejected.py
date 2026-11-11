"""get-content-cross-knowledge-base-isolation-rejected."""
from __future__ import annotations

import time
import urllib.request

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-content-cross-knowledge-base-isolation-rejected"
GROUP = "overly-permissive"
SERVICES = ["qconnect"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """GetContent for a real contentId scoped under the WRONG knowledgeBaseId is rejected as not found."""
    qc = ctx.client("qconnect")
    kb1_id = _create_active_knowledge_base(ctx, qc, "CUSTOM")
    kb2_id = _create_active_knowledge_base(ctx, qc, "CUSTOM")

    name = ctx.unique_name("sim2real-qc-content-")
    upload = qc.start_content_upload(knowledgeBaseId=kb1_id, contentType="text/plain")
    _put_bytes(ctx, upload["url"], upload["headersToInclude"], b"belongs to kb1 only")
    content_id = qc.create_content(
        knowledgeBaseId=kb1_id, name=name, uploadId=upload["uploadId"], tags={"sim2real": CHECK}
    )["content"]["contentId"]
    ctx.on_cleanup(
        lambda: _ignore_not_found(lambda: qc.delete_content(knowledgeBaseId=kb1_id, contentId=content_id))
    )
    status = _poll_until(
        lambda: qc.get_content(knowledgeBaseId=kb1_id, contentId=content_id)["content"]["status"],
        lambda s: s in ("ACTIVE", "CREATE_FAILED"),
        timeout_s=60.0,
        description="content reaching a terminal status",
    )
    assert status == "ACTIVE", f"expected content status ACTIVE, got {status}"

    code, message = _client_error(lambda: qc.get_content(knowledgeBaseId=kb2_id, contentId=content_id))
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException across KBs, got {code}"
    assert message == "Content does not exist.", f"unexpected message {message!r}"

    # positive control: the same contentId under its OWN knowledge base is visible
    own = qc.get_content(knowledgeBaseId=kb1_id, contentId=content_id)["content"]
    assert own["contentId"] == content_id, f"expected contentId {content_id}, got {own['contentId']}"
    assert own["knowledgeBaseId"] == kb1_id, f"expected knowledgeBaseId {kb1_id}, got {own['knowledgeBaseId']}"


def _create_active_knowledge_base(ctx, qc, kb_type: str) -> str:
    name = ctx.unique_name("sim2real-qc-kb-")
    kb_id = qc.create_knowledge_base(name=name, knowledgeBaseType=kb_type, tags={"sim2real": CHECK})[
        "knowledgeBase"
    ]["knowledgeBaseId"]
    ctx.on_cleanup(lambda: _ignore_not_found(lambda: qc.delete_knowledge_base(knowledgeBaseId=kb_id)))
    status = _poll_until(
        lambda: qc.get_knowledge_base(knowledgeBaseId=kb_id)["knowledgeBase"]["status"],
        lambda s: s in ("ACTIVE", "CREATE_FAILED"),
        timeout_s=60.0,
        description="knowledge base reaching a terminal status",
    )
    assert status == "ACTIVE", f"expected knowledge base status ACTIVE, got {status}"
    return kb_id


def _put_bytes(ctx, url: str, headers: dict, body: bytes) -> None:
    target_url, route_headers = ctx.endpoint_route(url)
    req = urllib.request.Request(url=target_url, data=body, method="PUT", headers={**dict(headers), **route_headers})
    with urllib.request.urlopen(req, timeout=30) as resp:
        assert 200 <= resp.status < 300, f"upload PUT failed with status {resp.status}"


def _client_error(fn):
    """Call fn(); return the (code, message) it is refused with. An unexpected success raises,
    so a target that accepts what AWS refuses reads as an acceptance, not a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _ignore_not_found(fn):
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0, description="condition"):
    deadline = time.monotonic() + timeout_s
    value = probe()
    while not predicate(value) and time.monotonic() < deadline:
        time.sleep(interval_s)
        value = probe()
    if not predicate(value):
        raise AssertionError(f"{description} not observed within {timeout_s}s; last saw {value!r}")
    return value


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
