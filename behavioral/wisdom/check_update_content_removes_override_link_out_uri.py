"""update-content-removes-override-link-out-uri."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "update-content-removes-override-link-out-uri"
GROUP = "state"
SERVICES = ["wisdom"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """UpdateContent with removeOverrideLinkOutUri=True clears a previously-set linkOutUri, and
    the field stays absent on a fresh GetContent -- a partial-update flag many emulators ignore."""
    wisdom = ctx.client("wisdom")
    kb = wisdom.create_knowledge_base(
        name=ctx.unique_name("sim2real-behav-kb-"),
        knowledgeBaseType="CUSTOM",
        tags={"team": "support", "stage": "sim2real-behav"},
    )["knowledgeBase"]
    kb_id = kb["knowledgeBaseId"]
    ctx.on_cleanup(lambda: _safe_delete(lambda: wisdom.delete_knowledge_base(knowledgeBaseId=kb_id)))
    _poll_until(
        lambda: wisdom.get_knowledge_base(knowledgeBaseId=kb_id)["knowledgeBase"],
        lambda k: k["status"] == "ACTIVE",
        timeout_s=60.0,
    )

    upload = wisdom.start_content_upload(knowledgeBaseId=kb_id, contentType="text/plain")
    _put_upload(ctx, upload, b"original link body")
    created = wisdom.create_content(
        knowledgeBaseId=kb_id,
        name=ctx.unique_name("sim2real-behav-content-"),
        uploadId=upload["uploadId"],
        overrideLinkOutUri="https://example.com/original-link",
        tags={"team": "support", "stage": "sim2real-behav"},
    )["content"]
    content_id = created["contentId"]
    ctx.on_cleanup(lambda: _safe_delete(lambda: wisdom.delete_content(knowledgeBaseId=kb_id, contentId=content_id)))

    active = _poll_until(
        lambda: wisdom.get_content(knowledgeBaseId=kb_id, contentId=content_id)["content"],
        lambda c: c["status"] in ("ACTIVE", "CREATE_FAILED"),
        timeout_s=60.0,
    )
    assert active["status"] == "ACTIVE", f"expected content to become ACTIVE, got {active['status']!r}"
    assert active["linkOutUri"] == "https://example.com/original-link", (
        f"expected the overrideLinkOutUri set at creation, got {active.get('linkOutUri')!r}"
    )

    updated = wisdom.update_content(
        knowledgeBaseId=kb_id,
        contentId=content_id,
        revisionId=active["revisionId"],
        removeOverrideLinkOutUri=True,
    )["content"]
    assert "linkOutUri" not in updated or updated.get("linkOutUri") is None, (
        f"expected linkOutUri cleared on the UpdateContent response, got {updated.get('linkOutUri')!r}"
    )

    final = wisdom.get_content(knowledgeBaseId=kb_id, contentId=content_id)["content"]
    assert "linkOutUri" not in final or final.get("linkOutUri") is None, (
        f"expected linkOutUri to stay absent on a fresh GetContent, got {final.get('linkOutUri')!r}"
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
