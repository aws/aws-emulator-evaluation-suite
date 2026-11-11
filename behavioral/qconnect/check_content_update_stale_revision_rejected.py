"""content-update-stale-revision-rejected."""
from __future__ import annotations

import time
import urllib.request

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "content-update-stale-revision-rejected"
GROUP = "state"
SERVICES = ["qconnect"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """UpdateContent with a stale revisionId is rejected; a fresh revisionId still succeeds."""
    qc = ctx.client("qconnect")
    kb_id = _create_active_knowledge_base(ctx, qc, "CUSTOM")

    name = ctx.unique_name("sim2real-qc-content-")
    upload = qc.start_content_upload(knowledgeBaseId=kb_id, contentType="text/plain")
    _put_bytes(ctx, upload["url"], upload["headersToInclude"], b"initial body")
    content = qc.create_content(
        knowledgeBaseId=kb_id, name=name, uploadId=upload["uploadId"], tags={"sim2real": CHECK}
    )["content"]
    content_id = content["contentId"]
    ctx.on_cleanup(
        lambda: _ignore_not_found(lambda: qc.delete_content(knowledgeBaseId=kb_id, contentId=content_id))
    )
    content_status = _poll_until(
        lambda: qc.get_content(knowledgeBaseId=kb_id, contentId=content_id)["content"]["status"],
        lambda s: s in ("ACTIVE", "CREATE_FAILED"),
        timeout_s=60.0,
    )
    assert content_status == "ACTIVE", f"expected content to become ACTIVE, got {content_status}"
    stale_revision = qc.get_content(knowledgeBaseId=kb_id, contentId=content_id)["content"]["revisionId"]

    # advance the revision so `stale_revision` is now out of date
    qc.update_content(knowledgeBaseId=kb_id, contentId=content_id, title="first-title-change")
    current = qc.get_content(knowledgeBaseId=kb_id, contentId=content_id)["content"]
    assert current["title"] == "first-title-change", f"expected title update to apply, got {current['title']!r}"
    assert current["revisionId"] != stale_revision, "revisionId must advance after a successful update"

    code, message = _client_error(
        lambda: qc.update_content(
            knowledgeBaseId=kb_id,
            contentId=content_id,
            title="should-not-apply",
            revisionId=stale_revision,
        )
    )
    assert code == "PreconditionFailedException", f"expected PreconditionFailedException, got {code}"
    assert message == "", f"AWS refuses a stale revisionId with an empty message, got {message!r}"

    unchanged = qc.get_content(knowledgeBaseId=kb_id, contentId=content_id)["content"]
    assert unchanged["title"] == "first-title-change", "stale-revision update must not have applied"

    fresh_revision = unchanged["revisionId"]
    qc.update_content(
        knowledgeBaseId=kb_id, contentId=content_id, title="second-title-change", revisionId=fresh_revision
    )
    applied = qc.get_content(knowledgeBaseId=kb_id, contentId=content_id)["content"]
    assert applied["title"] == "second-title-change", "update with a fresh revisionId must succeed"


def _create_active_knowledge_base(ctx, qc, kb_type: str) -> str:
    name = ctx.unique_name("sim2real-qc-kb-")
    kb_id = qc.create_knowledge_base(name=name, knowledgeBaseType=kb_type, tags={"sim2real": CHECK})[
        "knowledgeBase"
    ]["knowledgeBaseId"]
    ctx.on_cleanup(lambda: _ignore_not_found(lambda: qc.delete_knowledge_base(knowledgeBaseId=kb_id)))
    kb_status = _poll_until(
        lambda: qc.get_knowledge_base(knowledgeBaseId=kb_id)["knowledgeBase"]["status"],
        lambda s: s in ("ACTIVE", "CREATE_FAILED"),
        timeout_s=60.0,
    )
    assert kb_status == "ACTIVE", f"expected knowledge base to become ACTIVE, got {kb_status}"
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


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    value = probe()
    while not predicate(value):
        if time.monotonic() >= deadline:
            raise AssertionError(f"condition not met within {timeout_s}s; last saw {value!r}")
        time.sleep(interval_s)
        value = probe()
    return value


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
