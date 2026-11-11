"""create-content-invalid-upload-id-not-found."""
from __future__ import annotations

import time
import urllib.request
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-content-invalid-upload-id-not-found"
GROUP = "error-semantics"
SERVICES = ["wisdom"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """CreateContent with an uploadId StartContentUpload never issued fails with ValidationException and
    the exact "Invalid uploadId" message and lists no content; an issued uploadId yields ACTIVE content.
    """
    wisdom = ctx.client("wisdom")
    kb = wisdom.create_knowledge_base(name=ctx.unique_name("sim2real-kb-"), knowledgeBaseType="CUSTOM")[
        "knowledgeBase"
    ]
    kb_id = kb["knowledgeBaseId"]
    ctx.on_cleanup(lambda: wisdom.delete_knowledge_base(knowledgeBaseId=kb_id))

    bogus_upload_id = f"bogus-upload-{uuid.uuid4().hex}"
    bogus_name = ctx.unique_name("sim2real-content-")
    code, message = _error(
        lambda: wisdom.create_content(
            knowledgeBaseId=kb_id, name=bogus_name, uploadId=bogus_upload_id
        )
    )
    assert code == "ValidationException", f"expected a rejection, got {code!r}"
    assert message == "Invalid uploadId", f"expected the invalid-uploadId message, got {message!r}"

    # effect absent: the rejected call created nothing under its name (independent read)
    listed = wisdom.list_contents(knowledgeBaseId=kb_id)["contentSummaries"]
    assert not any(c["name"] == bogus_name for c in listed), (
        f"content named {bogus_name!r} should not exist after a rejected CreateContent, saw {listed!r}"
    )

    # positive control: a real StartContentUpload-issued uploadId is accepted
    upload_id = _upload_bytes(ctx, kb_id, "text/plain", b"legit body")
    content = wisdom.create_content(
        knowledgeBaseId=kb_id, name=ctx.unique_name("sim2real-content-"), uploadId=upload_id
    )["content"]
    content_id = content["contentId"]
    ctx.on_cleanup(lambda: wisdom.delete_content(knowledgeBaseId=kb_id, contentId=content_id))

    # terminal read: an independent GetContent, not the mutating call's own response
    final = _poll_until(
        lambda: wisdom.get_content(knowledgeBaseId=kb_id, contentId=content_id)["content"],
        lambda c: c["status"] in ("ACTIVE", "CREATE_FAILED"),
        timeout_s=60.0,
    )
    assert final["status"] == "ACTIVE", f"expected content to become ACTIVE, got {final['status']!r}"


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
