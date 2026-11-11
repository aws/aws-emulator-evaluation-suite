"""create-content-against-quick-responses-kb-rejected."""
from __future__ import annotations

import time
import urllib.request

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-content-against-quick-responses-kb-rejected"
GROUP = "overly-permissive"
SERVICES = ["wisdom"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """StartContentUpload on a QUICK_RESPONSES knowledge base fails with ValidationException and the exact
    unsupported-content-type message; on a CUSTOM knowledge base, upload then CreateContent reaches
    ACTIVE.
    """
    wisdom = ctx.client("wisdom")
    kb_qr = wisdom.create_knowledge_base(
        name=ctx.unique_name("sim2real-kbqr-"),
        knowledgeBaseType="QUICK_RESPONSES",
        tags={"team": "support", "stage": "sim2real-behav"},
    )["knowledgeBase"]
    kb_qr_id = kb_qr["knowledgeBaseId"]
    ctx.on_cleanup(lambda: wisdom.delete_knowledge_base(knowledgeBaseId=kb_qr_id))

    code, message = _error(lambda: wisdom.start_content_upload(knowledgeBaseId=kb_qr_id, contentType="text/plain"))
    assert code == "ValidationException", f"expected ValidationException, got {code!r}"
    assert message == "Unsupported ContentType for KnowledgeBaseType: quick_replies", (
        f"expected the unsupported-content-type message, got {message!r}"
    )

    # positive control: the identical flow against a CUSTOM knowledge base succeeds
    kb_custom = wisdom.create_knowledge_base(
        name=ctx.unique_name("sim2real-kbcustom-"),
        knowledgeBaseType="CUSTOM",
        tags={"team": "support", "stage": "sim2real-behav"},
    )["knowledgeBase"]
    kb_custom_id = kb_custom["knowledgeBaseId"]
    ctx.on_cleanup(lambda: wisdom.delete_knowledge_base(knowledgeBaseId=kb_custom_id))

    upload_id2 = _upload_bytes(ctx, kb_custom_id, "text/plain", b"right kb type body")
    name = ctx.unique_name("sim2real-content-")
    content = wisdom.create_content(knowledgeBaseId=kb_custom_id, name=name, uploadId=upload_id2)[
        "content"
    ]
    content_id = content["contentId"]
    ctx.on_cleanup(lambda: wisdom.delete_content(knowledgeBaseId=kb_custom_id, contentId=content_id))
    assert content["status"] in ("CREATE_IN_PROGRESS", "ACTIVE"), content["status"]

    # terminal read: independent of the mutating call, at the destination
    final = _poll_until(
        lambda: wisdom.get_content(knowledgeBaseId=kb_custom_id, contentId=content_id)["content"],
        lambda c: c["status"] in ("ACTIVE", "CREATE_FAILED"),
        timeout_s=60.0,
    )
    assert final["status"] == "ACTIVE", f"expected ACTIVE, got {final['status']!r}"


def _error(fn):
    """Return the (code, message) of the ClientError fn() raises; a success fails the check."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message", "")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


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
