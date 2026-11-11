"""content-update-persists-title-and-bumps-revision."""
from __future__ import annotations

import time
import urllib.request

from behavioral_harness import tags

CHECK = "content-update-persists-title-and-bumps-revision"
GROUP = "data-plane"
SERVICES = ["wisdom"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """UpdateContent persists the new title and returns a revisionId distinct from the original, and the
    change is visible on a fresh GetContent."""
    wisdom = ctx.client("wisdom")
    kb = wisdom.create_knowledge_base(
        name=ctx.unique_name("sim2real-kb-"),
        knowledgeBaseType="CUSTOM",
        tags={"team": "support", "stage": "sim2real-behav"},
    )["knowledgeBase"]
    kb_id = kb["knowledgeBaseId"]
    ctx.on_cleanup(lambda: wisdom.delete_knowledge_base(knowledgeBaseId=kb_id))

    upload_id = _upload_bytes(ctx, kb_id, "text/plain", b"initial body")
    content = wisdom.create_content(
        knowledgeBaseId=kb_id,
        name=ctx.unique_name("sim2real-content-"),
        uploadId=upload_id,
        title="Original Title",
        tags={"team": "support", "stage": "sim2real-behav"},
    )["content"]
    content_id = content["contentId"]
    ctx.on_cleanup(lambda: wisdom.delete_content(knowledgeBaseId=kb_id, contentId=content_id))

    active = _poll_until(
        lambda: wisdom.get_content(knowledgeBaseId=kb_id, contentId=content_id)["content"],
        lambda c: c["status"] in ("ACTIVE", "CREATE_FAILED"),
        timeout_s=60.0,
    )
    assert active["status"] == "ACTIVE", f"content failed to activate: {active!r}"
    original_revision = active["revisionId"]
    assert active["title"] == "Original Title", (
        f"expected freshly-created title 'Original Title', got {active['title']!r}"
    )

    updated = wisdom.update_content(
        knowledgeBaseId=kb_id,
        contentId=content_id,
        revisionId=original_revision,
        title="Updated Title",
    )["content"]
    assert updated["title"] == "Updated Title", (
        f"UpdateContent response should echo new title 'Updated Title', got {updated['title']!r}"
    )
    assert updated["revisionId"] != original_revision, (
        f"UpdateContent must bump revisionId past {original_revision!r}, got the same value back"
    )

    refetched = wisdom.get_content(knowledgeBaseId=kb_id, contentId=content_id)["content"]
    assert refetched["title"] == "Updated Title", (
        f"independent GetContent expected persisted title 'Updated Title', got {refetched['title']!r}"
    )
    assert refetched["revisionId"] == updated["revisionId"], (
        f"independent GetContent expected revisionId {updated['revisionId']!r}, "
        f"got {refetched['revisionId']!r}"
    )


def _poll_until(probe, predicate, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")


def _upload_bytes(ctx, kb_id, content_type, data):
    wisdom = ctx.client("wisdom")
    up = wisdom.start_content_upload(knowledgeBaseId=kb_id, contentType=content_type)
    url, route = ctx.endpoint_route(up["url"])
    req = urllib.request.Request(
        url, data=data, method="PUT", headers=dict(up.get("headersToInclude", {}), **route)
    )
    with urllib.request.urlopen(req, timeout=30) as http_resp:
        if http_resp.status not in (200, 201, 204):
            raise AssertionError(f"content upload PUT failed with status {http_resp.status}")
    return up["uploadId"]


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
