"""content-search-finds-created."""
from __future__ import annotations

import time
import urllib.request

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "content-search-finds-created"
GROUP = "data-plane"
SERVICES = ["qconnect"]


@tags("axis:happy-path", "cap:c2", "cap:c4", "concern:data-plane", "dp:api", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """SearchContent finds active content in a CUSTOM knowledge base by an exact-name filter."""
    qc = ctx.client("qconnect")
    kb_id = _create_active_knowledge_base(ctx, qc, "CUSTOM")

    name = ctx.unique_name("sim2real-qc-content-searchable-")
    upload = qc.start_content_upload(knowledgeBaseId=kb_id, contentType="text/plain")
    _put_bytes(ctx, upload["url"], upload["headersToInclude"], b"searchable document body")
    content_id = qc.create_content(
        knowledgeBaseId=kb_id, name=name, uploadId=upload["uploadId"], tags={"sim2real": "true"}
    )["content"]["contentId"]
    ctx.on_cleanup(
        lambda: _ignore_not_found(lambda: qc.delete_content(knowledgeBaseId=kb_id, contentId=content_id))
    )
    content_status = _poll_until(
        lambda: qc.get_content(knowledgeBaseId=kb_id, contentId=content_id)["content"]["status"],
        lambda s: s in ("ACTIVE", "CREATE_FAILED"),
        timeout_s=60.0,
    )
    assert content_status == "ACTIVE", f"content did not reach ACTIVE, got {content_status}"

    def _search_hits():
        resp = qc.search_content(
            knowledgeBaseId=kb_id,
            searchExpression={"filters": [{"field": "NAME", "operator": "EQUALS", "value": name}]},
        )
        return {c["contentId"] for c in resp["contentSummaries"]}

    hits = _poll_until(_search_hits, lambda h: content_id in h, timeout_s=60.0, interval_s=3.0)
    assert content_id in hits, f"expected content {content_id} in search results, got {hits}"


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
