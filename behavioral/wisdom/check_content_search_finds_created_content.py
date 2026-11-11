"""content-search-finds-created-content."""
from __future__ import annotations

import time
import urllib.request

from behavioral_harness import tags

CHECK = "content-search-finds-created-content"
GROUP = "data-plane"
SERVICES = ["wisdom"]


@tags("axis:happy-path", "cap:c2", "cap:c4", "concern:data-plane", "dp:api", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """SearchContent with a NAME/EQUALS filter finds the content that was just created and ACTIVE."""
    wisdom = ctx.client("wisdom")
    kb = wisdom.create_knowledge_base(
        name=ctx.unique_name("sim2real-kb-"),
        knowledgeBaseType="CUSTOM",
        tags={"team": "support", "stage": "sim2real-behav"},
    )["knowledgeBase"]
    kb_id = kb["knowledgeBaseId"]
    ctx.on_cleanup(lambda: wisdom.delete_knowledge_base(knowledgeBaseId=kb_id))

    name = ctx.unique_name("sim2real-content-")
    upload_id = _upload_bytes(ctx, kb_id, "text/plain", b"searchable body")
    content = wisdom.create_content(
        knowledgeBaseId=kb_id,
        name=name,
        uploadId=upload_id,
        tags={"team": "support", "stage": "sim2real-behav"},
    )["content"]
    content_id = content["contentId"]
    ctx.on_cleanup(lambda: wisdom.delete_content(knowledgeBaseId=kb_id, contentId=content_id))

    _poll_until(
        lambda: wisdom.get_content(knowledgeBaseId=kb_id, contentId=content_id)["content"],
        lambda c: c["status"] == "ACTIVE",
        timeout_s=60.0,
    )

    def _search():
        return wisdom.search_content(
            knowledgeBaseId=kb_id,
            searchExpression={"filters": [{"field": "NAME", "operator": "EQUALS", "value": name}]},
        )["contentSummaries"]

    found = _poll_until(_search, lambda summaries: len(summaries) >= 1, timeout_s=60.0)
    match = next((s for s in found if s["contentId"] == content_id), None)
    assert match is not None, f"content {content_id} not among search results: {found!r}"
    assert match["name"] == name, f"expected name {name!r}, got {match['name']!r}"
    assert match["status"] == "ACTIVE", f"expected status ACTIVE, got {match['status']!r}"


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
