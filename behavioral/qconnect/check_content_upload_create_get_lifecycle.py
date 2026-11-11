"""content-upload-create-get-lifecycle."""
from __future__ import annotations

import time
import urllib.request

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "content-upload-create-get-lifecycle"
GROUP = "lifecycle"
SERVICES = ["qconnect"]


@tags("axis:happy-path", "cap:c1", "concern:data-plane", "concern:representation", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """StartContentUpload + CreateContent produces ACTIVE content with a working download URL."""
    qc = ctx.client("qconnect")
    kb_id = _create_active_knowledge_base(ctx, qc, "CUSTOM")

    body = b"This is the sim2real behavioral test document body."
    upload = qc.start_content_upload(knowledgeBaseId=kb_id, contentType="text/plain")
    _put_bytes(ctx, upload["url"], upload["headersToInclude"], body)

    name = ctx.unique_name("sim2real-qc-content-")
    content = qc.create_content(
        knowledgeBaseId=kb_id, name=name, uploadId=upload["uploadId"], tags={"sim2real": "true"}
    )["content"]
    content_id = content["contentId"]
    ctx.on_cleanup(
        lambda: _ignore_not_found(lambda: qc.delete_content(knowledgeBaseId=kb_id, contentId=content_id))
    )

    status = _poll_until(
        lambda: qc.get_content(knowledgeBaseId=kb_id, contentId=content_id)["content"]["status"],
        lambda s: s in ("ACTIVE", "CREATE_FAILED"),
        timeout_s=60.0,
    )
    assert status == "ACTIVE", f"content did not reach ACTIVE, got {status}"

    final = qc.get_content(knowledgeBaseId=kb_id, contentId=content_id)["content"]
    assert final["name"] == name, f"expected name {name}, got {final['name']}"
    assert final["url"], "expected a download url on the active content"
    assert final["revisionId"], "expected a revisionId on the active content"

    downloaded = _get_bytes(ctx, final["url"])
    assert downloaded == body, f"download url served {downloaded!r}, expected the uploaded body {body!r}"


def _create_active_knowledge_base(ctx, qc, kb_type: str) -> str:
    name = ctx.unique_name("sim2real-qc-kb-")
    kb_id = qc.create_knowledge_base(name=name, knowledgeBaseType=kb_type, tags={"sim2real": "true"})[
        "knowledgeBase"
    ]["knowledgeBaseId"]
    ctx.on_cleanup(lambda: _ignore_not_found(lambda: qc.delete_knowledge_base(knowledgeBaseId=kb_id)))
    status = _poll_until(
        lambda: qc.get_knowledge_base(knowledgeBaseId=kb_id)["knowledgeBase"]["status"],
        lambda s: s in ("ACTIVE", "CREATE_FAILED"),
        timeout_s=60.0,
    )
    assert status == "ACTIVE", f"knowledge base did not reach ACTIVE, got {status}"
    return kb_id


def _put_bytes(ctx, url: str, headers: dict, body: bytes) -> None:
    target_url, route_headers = ctx.endpoint_route(url)
    req = urllib.request.Request(url=target_url, data=body, method="PUT", headers={**dict(headers), **route_headers})
    with urllib.request.urlopen(req, timeout=30) as resp:
        assert 200 <= resp.status < 300, f"upload PUT failed with status {resp.status}"


def _get_bytes(ctx, url: str) -> bytes:
    target_url, route_headers = ctx.endpoint_route(url)
    with urllib.request.urlopen(urllib.request.Request(target_url, headers=route_headers), timeout=30) as resp:
        assert 200 <= resp.status < 300, f"download GET failed with status {resp.status}"
        return resp.read()


def _ignore_not_found(fn):
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    value = probe()
    while not predicate(value) and time.monotonic() < deadline:
        time.sleep(interval_s)
        value = probe()
    return value


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
