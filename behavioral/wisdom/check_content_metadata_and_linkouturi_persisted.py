"""content-metadata-and-linkouturi-persisted."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "content-metadata-and-linkouturi-persisted"
GROUP = "data-plane"
SERVICES = ["wisdom"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:data-plane", "concern:representation", "dp:api", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """CreateContent's metadata map and overrideLinkOutUri are persisted verbatim and returned
    unchanged by a subsequent GetContent -- fields many emulators accept but silently drop."""
    wisdom = ctx.client("wisdom")
    kb = wisdom.create_knowledge_base(
        name=ctx.unique_name("sim2real-behav-kb-"),
        knowledgeBaseType="CUSTOM",
        tags={"sim2real-behav": "true"},
    )["knowledgeBase"]
    kb_id = kb["knowledgeBaseId"]
    ctx.on_cleanup(lambda: _safe_delete(lambda: wisdom.delete_knowledge_base(knowledgeBaseId=kb_id)))
    _poll_until(
        lambda: wisdom.get_knowledge_base(knowledgeBaseId=kb_id)["knowledgeBase"],
        lambda k: k["status"] == "ACTIVE",
        timeout_s=60.0,
    )

    upload = wisdom.start_content_upload(knowledgeBaseId=kb_id, contentType="text/plain")
    _put_upload(ctx, upload, b"content-metadata-and-link-out-uri-persisted body")
    created = wisdom.create_content(
        knowledgeBaseId=kb_id,
        name=ctx.unique_name("sim2real-behav-content-"),
        uploadId=upload["uploadId"],
        metadata={"source": "sim2real", "version": "1"},
        overrideLinkOutUri="https://example.com/behavioral-check-doc",
        tags={"sim2real-behav": "true"},
    )["content"]
    content_id = created["contentId"]
    ctx.on_cleanup(lambda: _safe_delete(lambda: wisdom.delete_content(knowledgeBaseId=kb_id, contentId=content_id)))

    assert created["metadata"] == {"source": "sim2real", "version": "1"}, (
        f"expected CreateContent response metadata {{'source': 'sim2real', 'version': '1'}}, got {created['metadata']!r}"
    )
    assert created["linkOutUri"] == "https://example.com/behavioral-check-doc", (
        f"expected CreateContent response linkOutUri 'https://example.com/behavioral-check-doc', got {created['linkOutUri']!r}"
    )

    final = _poll_until(
        lambda: wisdom.get_content(knowledgeBaseId=kb_id, contentId=content_id)["content"],
        lambda c: c["status"] in ("ACTIVE", "CREATE_FAILED"),
        timeout_s=60.0,
    )
    assert final["status"] == "ACTIVE", f"expected content status ACTIVE, got {final['status']!r}"
    assert final["metadata"] == {"source": "sim2real", "version": "1"}, (
        f"expected GetContent metadata {{'source': 'sim2real', 'version': '1'}}, got {final['metadata']!r}"
    )
    assert final["linkOutUri"] == "https://example.com/behavioral-check-doc", (
        f"expected GetContent linkOutUri 'https://example.com/behavioral-check-doc', got {final['linkOutUri']!r}"
    )


def _put_upload(ctx, upload, data):
    import urllib.request

    target_url, route_headers = ctx.endpoint_route(upload["url"])
    req = urllib.request.Request(
        target_url, data=data, method="PUT", headers={**upload.get("headersToInclude", {}), **route_headers}
    )
    with urllib.request.urlopen(req, timeout=30) as resp:
        if resp.status not in (200, 201, 204):
            raise AssertionError(f"content upload PUT failed with status {resp.status}")


def _safe_delete(fn):
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last value={last!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)

