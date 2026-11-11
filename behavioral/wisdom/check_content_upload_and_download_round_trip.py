"""content-upload-and-download-round-trip."""
from __future__ import annotations

import time
import urllib.request
import uuid

from behavioral_harness import tags

CHECK = "content-upload-and-download-round-trip"
GROUP = "data-plane"
SERVICES = ["wisdom"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:data-plane", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """Bytes PUT to the StartContentUpload presigned URL are the exact bytes served back from the
    GetContent presigned download URL once the content reaches ACTIVE -- the core data-plane round trip
    an emulator that merely fakes the presigned URLs cannot pass."""
    wisdom = ctx.client("wisdom")
    kb = wisdom.create_knowledge_base(
        name=ctx.unique_name("sim2real-kb-"),
        knowledgeBaseType="CUSTOM",
        tags={"team": "support", "stage": "sim2real-behav"},
    )["knowledgeBase"]
    kb_id = kb["knowledgeBaseId"]
    ctx.on_cleanup(lambda: wisdom.delete_knowledge_base(knowledgeBaseId=kb_id))

    marker = uuid.uuid4().hex
    payload = f"sim2real wisdom content round-trip marker={marker}".encode("utf-8")
    upload_id = _upload_bytes(ctx, kb_id, "text/plain", payload)

    content = wisdom.create_content(
        knowledgeBaseId=kb_id, name=ctx.unique_name("sim2real-content-"), uploadId=upload_id
    )["content"]
    content_id = content["contentId"]
    ctx.on_cleanup(lambda: wisdom.delete_content(knowledgeBaseId=kb_id, contentId=content_id))

    active = _poll_until(
        lambda: wisdom.get_content(knowledgeBaseId=kb_id, contentId=content_id)["content"],
        lambda c: c["status"] == "ACTIVE",
        timeout_s=60.0,
    )
    downloaded = _http_get_bytes(ctx, active["url"])
    assert downloaded == payload, (
        f"downloaded bytes did not match uploaded bytes: expected {payload!r}, got {downloaded!r}"
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
    target_url, route_headers = ctx.endpoint_route(up["url"])
    req = urllib.request.Request(
        target_url, data=data, method="PUT", headers={**up.get("headersToInclude", {}), **route_headers}
    )
    with urllib.request.urlopen(req, timeout=30) as http_resp:
        if http_resp.status not in (200, 201, 204):
            raise AssertionError(f"content upload PUT failed with status {http_resp.status}")
    return up["uploadId"]


def _http_get_bytes(ctx, url):
    target_url, route_headers = ctx.endpoint_route(url)
    with urllib.request.urlopen(urllib.request.Request(target_url, headers=route_headers), timeout=30) as resp:
        return resp.read()


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
