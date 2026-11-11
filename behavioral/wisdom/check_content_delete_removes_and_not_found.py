"""content-delete-removes-and-not-found."""
from __future__ import annotations

import time
import urllib.request

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "content-delete-removes-and-not-found"
GROUP = "state"
SERVICES = ["wisdom"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """DeleteContent removes it; a subsequent GetContent returns ResourceNotFoundException,
    and a second DeleteContent on the same now-dead id also fails with ResourceNotFoundException
    rather than silently no-oping."""
    wisdom = ctx.client("wisdom")
    kb = wisdom.create_knowledge_base(
        name=ctx.unique_name("sim2real-kb-"),
        knowledgeBaseType="CUSTOM",
        tags={"team": "support", "stage": "sim2real-behav"},
    )["knowledgeBase"]
    kb_id = kb["knowledgeBaseId"]
    ctx.on_cleanup(lambda: wisdom.delete_knowledge_base(knowledgeBaseId=kb_id))

    upload_id = _upload_bytes(ctx, kb_id, "text/plain", b"delete-me content body")
    content = wisdom.create_content(
        knowledgeBaseId=kb_id, name=ctx.unique_name("sim2real-content-"), uploadId=upload_id
    )["content"]
    content_id = content["contentId"]

    _poll_until(
        lambda: wisdom.get_content(knowledgeBaseId=kb_id, contentId=content_id)["content"],
        lambda c: c["status"] == "ACTIVE",
        timeout_s=60.0,
    )

    wisdom.delete_content(knowledgeBaseId=kb_id, contentId=content_id)
    _poll_not_found(
        lambda: wisdom.get_content(knowledgeBaseId=kb_id, contentId=content_id), timeout_s=60.0
    )

    code, message = _error(lambda: wisdom.get_content(knowledgeBaseId=kb_id, contentId=content_id))
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code}"
    assert message == "Content does not exist.", f"expected the content not-found message, got {message!r}"

    # mutation on the dead id also fails: a second delete must not silently no-op
    redelete_code, redelete_message = _error(
        lambda: wisdom.delete_content(knowledgeBaseId=kb_id, contentId=content_id)
    )
    assert redelete_code == "ResourceNotFoundException", (
        f"expected a second DeleteContent on an already-deleted content to raise "
        f"ResourceNotFoundException, got {redelete_code}"
    )
    assert redelete_message == "Content does not exist.", (
        f"expected the content not-found message on re-delete, got {redelete_message!r}"
    )


def _error(fn):
    """Return the (code, message) of the ClientError fn() raises; a success fails the check."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message", "")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


def _poll_until(probe, predicate, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")


def _poll_not_found(get_fn, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            get_fn()
        except ClientError as err:
            if err.response["Error"]["Code"] == "ResourceNotFoundException":
                return
            raise
        time.sleep(interval_s)
    raise AssertionError("resource was not removed within timeout")


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
