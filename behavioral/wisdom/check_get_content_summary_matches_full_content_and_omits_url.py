"""get-content-summary-matches-full-content-and-omits-url."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "get-content-summary-matches-full-content-and-omits-url"
GROUP = "data-plane"
SERVICES = ["wisdom"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """GetContentSummary reports the same name/title/contentType/status/revisionId as GetContent
    for the same content item, but never carries the sensitive presigned download URL that
    GetContent exposes."""
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

    content_name = ctx.unique_name("sim2real-behav-content-")
    upload = wisdom.start_content_upload(knowledgeBaseId=kb_id, contentType="text/plain")
    _put_upload(ctx, upload, b"summary parity body")
    created = wisdom.create_content(
        knowledgeBaseId=kb_id,
        name=content_name,
        title="Summary Parity Title",
        uploadId=upload["uploadId"],
        tags={"team": "support", "stage": "sim2real-behav"},
    )["content"]
    content_id = created["contentId"]
    ctx.on_cleanup(lambda: _safe_delete(lambda: wisdom.delete_content(knowledgeBaseId=kb_id, contentId=content_id)))

    full = _poll_until(
        lambda: wisdom.get_content(knowledgeBaseId=kb_id, contentId=content_id)["content"],
        lambda c: c["status"] in ("ACTIVE", "CREATE_FAILED"),
        timeout_s=60.0,
    )
    assert full["status"] == "ACTIVE", f"expected content ACTIVE, got {full['status']!r}"
    assert "url" in full and full["url"], f"GetContent must carry a download url, got {full.get('url')!r}"

    summary = wisdom.get_content_summary(knowledgeBaseId=kb_id, contentId=content_id)["contentSummary"]
    assert summary["name"] == full["name"] == content_name, (
        f"name mismatch: summary={summary['name']!r} full={full['name']!r} expected={content_name!r}"
    )
    assert summary["title"] == full["title"] == "Summary Parity Title", (
        f"title mismatch: summary={summary['title']!r} full={full['title']!r}"
    )
    assert summary["contentType"] == full["contentType"], (
        f"contentType mismatch: summary={summary['contentType']!r} full={full['contentType']!r}"
    )
    assert summary["status"] == full["status"], f"status mismatch: summary={summary['status']!r} full={full['status']!r}"
    assert summary["revisionId"] == full["revisionId"], (
        f"revisionId mismatch: summary={summary['revisionId']!r} full={full['revisionId']!r}"
    )
    assert "url" not in summary, f"GetContentSummary must omit the presigned url, got {summary.get('url')!r}"


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
