"""untag-resource-after-delete-blocked."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "untag-resource-after-delete-blocked"
GROUP = "overly-permissive"
SERVICES = ["opensearchserverless"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UntagResource against an already-deleted collection ARN is rejected with
    ResourceNotFoundException rather than silently accepted; the same call
    succeeds normally against a live collection (positive control)."""
    osc = ctx.client("opensearchserverless")

    # Doomed collection: create, tag implicitly via CreateCollection tags, delete it,
    # then try to untag it.
    doomed_name = ctx.unique_name("sim2real-untag-doomed-")
    doomed_enc_name = _short_name(ctx, "sim2real-untagdoomenc-")
    osc.create_security_policy(
        type="encryption",
        name=doomed_enc_name,
        policy=json.dumps(
            {"Rules": [{"ResourceType": "collection", "Resource": [f"collection/{doomed_name}"]}], "AWSOwnedKey": True}
        ),
    )
    ctx.on_cleanup(lambda: _teardown(lambda: osc.delete_security_policy(type="encryption", name=doomed_enc_name)))
    doomed = osc.create_collection(
        name=doomed_name,
        type="SEARCH",
        standbyReplicas="DISABLED",
        tags=[{"key": "team", "value": "sim2real"}],
    )["createCollectionDetail"]
    doomed_id, doomed_arn = doomed["id"], doomed["arn"]
    ctx.on_cleanup(lambda: _best_effort_delete_collection(osc, doomed_id))
    _wait_collection_active(osc, doomed_id, timeout_s=600)

    osc.delete_collection(id=doomed_id)
    _wait_collection_removed(osc, doomed_id, timeout_s=600)

    code, message = _expect_error(lambda: osc.untag_resource(resourceArn=doomed_arn, tagKeys=["team"]))
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code!r}"
    expected_message = f"Collection ID {doomed_id} is not found"
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # Positive control in the same file: UntagResource against a live collection
    # succeeds and the tag is actually gone afterwards.
    live_name = ctx.unique_name("sim2real-untag-live-")
    live_enc_name = _short_name(ctx, "sim2real-untagliveenc-")
    osc.create_security_policy(
        type="encryption",
        name=live_enc_name,
        policy=json.dumps(
            {"Rules": [{"ResourceType": "collection", "Resource": [f"collection/{live_name}"]}], "AWSOwnedKey": True}
        ),
    )
    ctx.on_cleanup(lambda: _teardown(lambda: osc.delete_security_policy(type="encryption", name=live_enc_name)))
    live = osc.create_collection(
        name=live_name,
        type="SEARCH",
        standbyReplicas="DISABLED",
        tags=[{"key": "team", "value": "sim2real"}],
    )["createCollectionDetail"]
    live_id, live_arn = live["id"], live["arn"]
    ctx.on_cleanup(lambda: _best_effort_delete_collection(osc, live_id))
    _wait_collection_active(osc, live_id, timeout_s=600)

    osc.untag_resource(resourceArn=live_arn, tagKeys=["team"])
    tags = osc.list_tags_for_resource(resourceArn=live_arn)["tags"]
    assert all(t["key"] != "team" for t in tags), f"tag 'team' was not removed: {tags}"


# ===== self-contained helpers =====
def _short_name(ctx, prefix, maxlen=32):
    name = ctx.unique_name(prefix)
    if len(name) <= maxlen:
        return name
    return name[: maxlen - 1].rstrip("-") + "z"


def _teardown(fn, timeout_s=135.0):
    """Teardown call: an absent resource is done, ConflictException (a collection still CREATING)
    or ValidationException (a policy still in use) is retried every 2 s to the deadline, which
    keeps all of the check's teardowns inside its cleanup budget; every other error raises."""
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    while True:
        try:
            fn()
            return
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code == "ResourceNotFoundException":
                return
            if code not in ("ConflictException", "ValidationException") or time.monotonic() >= deadline:
                raise
        time.sleep(2)


def _expect_error(fn):
    """Return the error code and message of a call that must be rejected. An unexpected
    SUCCESS raises, so an over-permissive target's acceptance is reported as such rather than
    as a plain code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        error = exc.response["Error"]
        return error["Code"], error.get("Message", "")
    raise AssertionError(f"expected this call to be rejected, but it SUCCEEDED and returned {result!r}")


def _best_effort_delete_collection(osc, collection_id):
    _teardown(lambda: osc.delete_collection(id=collection_id))


def _wait_collection_active(osc, collection_id, timeout_s=600, interval_s=10):
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        details = osc.batch_get_collection(ids=[collection_id]).get("collectionDetails", [])
        if details:
            status = details[0]["status"]
            if status == "ACTIVE":
                return
            if status == "FAILED":
                raise AssertionError(f"collection {collection_id} entered FAILED state while creating")
        time.sleep(interval_s)
    raise AssertionError(f"collection {collection_id} never became ACTIVE within {timeout_s}s")


def _wait_collection_removed(osc, collection_id, timeout_s=600, interval_s=10):
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        details = osc.batch_get_collection(ids=[collection_id]).get("collectionDetails", [])
        if not details:
            return
        time.sleep(interval_s)
    raise AssertionError(f"collection {collection_id} was never fully removed within {timeout_s}s")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
