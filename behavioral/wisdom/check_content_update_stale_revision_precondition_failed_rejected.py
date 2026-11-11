"""content-update-stale-revision-precondition-failed-rejected."""
from __future__ import annotations

import time
import urllib.request

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "content-update-stale-revision-precondition-failed-rejected"
GROUP = "overly-permissive"
SERVICES = ["wisdom"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """UpdateContent with a stale revisionId is rejected with PreconditionFailedException and leaves the
    content's title/revisionId unchanged, while a subsequent update using the CURRENT revisionId still
    succeeds (optimistic-locking boundary)."""
    wisdom = ctx.client("wisdom")
    kb = wisdom.create_knowledge_base(name=ctx.unique_name("sim2real-kb-"), knowledgeBaseType="CUSTOM")[
        "knowledgeBase"
    ]
    kb_id = kb["knowledgeBaseId"]
    ctx.on_cleanup(lambda: wisdom.delete_knowledge_base(knowledgeBaseId=kb_id))

    upload_id = _upload_bytes(ctx, kb_id, "text/plain", b"body v0")
    content = wisdom.create_content(
        knowledgeBaseId=kb_id,
        name=ctx.unique_name("sim2real-content-"),
        uploadId=upload_id,
        title="Title V0",
    )["content"]
    content_id = content["contentId"]
    ctx.on_cleanup(lambda: wisdom.delete_content(knowledgeBaseId=kb_id, contentId=content_id))

    active = _poll_until(
        lambda: wisdom.get_content(knowledgeBaseId=kb_id, contentId=content_id)["content"],
        lambda c: c["status"] == "ACTIVE",
        timeout_s=60.0,
    )
    stale_revision = active["revisionId"]

    first_update = wisdom.update_content(
        knowledgeBaseId=kb_id, contentId=content_id, revisionId=stale_revision, title="Title V1"
    )["content"]
    current_revision = first_update["revisionId"]
    assert current_revision != stale_revision, (
        f"expected UpdateContent to bump revisionId, got same value {current_revision!r}"
    )

    code, message = _error(
        lambda: wisdom.update_content(
            knowledgeBaseId=kb_id,
            contentId=content_id,
            revisionId=stale_revision,
            title="Title V1 Stale Attempt",
        )
    )
    assert code == "PreconditionFailedException", (
        f"expected PreconditionFailedException for a stale revisionId, got {code!r}"
    )
    # AWS sends this refusal with an empty message
    assert message == "", f"expected an empty PreconditionFailedException message, got {message!r}"

    unchanged = wisdom.get_content(knowledgeBaseId=kb_id, contentId=content_id)["content"]
    assert unchanged["title"] == "Title V1", (
        f"expected the rejected update to leave title as 'Title V1', got {unchanged['title']!r}"
    )
    assert unchanged["revisionId"] == current_revision, (
        f"expected the rejected update to leave revisionId as {current_revision!r}, got "
        f"{unchanged['revisionId']!r}"
    )

    # positive control: updating with the CURRENT revisionId still succeeds
    second_update = wisdom.update_content(
        knowledgeBaseId=kb_id, contentId=content_id, revisionId=current_revision, title="Title V2"
    )["content"]
    assert second_update["title"] == "Title V2", (
        f"expected UpdateContent to return title 'Title V2', got {second_update['title']!r}"
    )
    final_revision = second_update["revisionId"]
    assert final_revision != current_revision, (
        f"expected UpdateContent to bump revisionId again, got same value {final_revision!r}"
    )

    # terminal read is independent of the mutating UpdateContent call
    final = wisdom.get_content(knowledgeBaseId=kb_id, contentId=content_id)["content"]
    assert final["title"] == "Title V2", (
        f"expected GetContent to show title 'Title V2', got {final['title']!r}"
    )
    assert final["revisionId"] == final_revision, (
        f"expected GetContent revisionId {final_revision!r}, got {final['revisionId']!r}"
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
