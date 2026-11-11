"""create-content-duplicate-name-conflict-rejected."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "create-content-duplicate-name-conflict-rejected"
GROUP = "content"
SERVICES = ["wisdom"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """CreateContent with a name that already identifies existing content in the same knowledge
    base is rejected with ConflictException; no second content item is created, and creating
    content with a distinct name (positive control) succeeds."""
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

    shared_name = ctx.unique_name("sim2real-behav-dupname-")
    upload1 = wisdom.start_content_upload(knowledgeBaseId=kb_id, contentType="text/plain")
    _put_upload(ctx, upload1, b"first content body")
    first = wisdom.create_content(
        knowledgeBaseId=kb_id,
        name=shared_name,
        uploadId=upload1["uploadId"],
        tags={"team": "support", "stage": "sim2real-behav"},
    )["content"]
    first_id = first["contentId"]
    ctx.on_cleanup(lambda: _safe_delete(lambda: wisdom.delete_content(knowledgeBaseId=kb_id, contentId=first_id)))
    _poll_until(
        lambda: wisdom.get_content(knowledgeBaseId=kb_id, contentId=first_id)["content"],
        lambda c: c["status"] in ("ACTIVE", "CREATE_FAILED"),
        timeout_s=60.0,
    )

    # break exactly one thing: create a second content item with the same name
    upload2 = wisdom.start_content_upload(knowledgeBaseId=kb_id, contentType="text/plain")
    _put_upload(ctx, upload2, b"second content body")
    error, message = _error(
        lambda: wisdom.create_content(knowledgeBaseId=kb_id, name=shared_name, uploadId=upload2["uploadId"])
    )
    assert error == "ConflictException", f"expected ConflictException for duplicate name, got {error!r}"
    assert message == "Name is already in use", f"expected the name-in-use message, got {message!r}"

    # effect absent: only the original content item with this name exists
    listed = wisdom.list_contents(knowledgeBaseId=kb_id)["contentSummaries"]
    matching = [c for c in listed if c["name"] == shared_name]
    assert len(matching) == 1, f"expected exactly 1 content item named {shared_name!r}, found {len(matching)}"
    assert matching[0]["contentId"] == first_id, (
        f"expected surviving content id {first_id!r}, found {matching[0]['contentId']!r}"
    )

    # positive control: a distinct name succeeds
    upload3 = wisdom.start_content_upload(knowledgeBaseId=kb_id, contentType="text/plain")
    _put_upload(ctx, upload3, b"third content body")
    other_name = ctx.unique_name("sim2real-behav-otherscontent-")
    second = wisdom.create_content(
        knowledgeBaseId=kb_id,
        name=other_name,
        uploadId=upload3["uploadId"],
        tags={"team": "support", "stage": "sim2real-behav"},
    )["content"]
    assert second["contentId"] != first_id, (
        f"expected a distinct content id for {other_name!r}, got the duplicate's id {first_id!r}"
    )
    ctx.on_cleanup(
        lambda: _safe_delete(lambda: wisdom.delete_content(knowledgeBaseId=kb_id, contentId=second["contentId"]))
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


def _error(fn):
    """Return the (code, message) of the ClientError fn() raises; a success fails the check."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message", "")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


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
