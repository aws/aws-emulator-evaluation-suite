"""tag-and-untag-resource-round-trip."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "tag-and-untag-resource-round-trip"
GROUP = "tags"
SERVICES = ["networkflowmonitor"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control", "resource:account-singleton:networkflowmonitor-scope")
def run(ctx) -> None:
    """TagResource/UntagResource on a scope round-trip through ListTagsForResource."""
    nfm = ctx.client("networkflowmonitor")
    account_id = ctx.client("sts").get_caller_identity()["Account"]

    target = {"targetIdentifier": {"targetId": {"accountId": account_id}, "targetType": "ACCOUNT"}, "region": ctx.region}
    scope = _acquire_scope(ctx, nfm, target)
    scope_arn = scope["scopeArn"]

    tags_before = nfm.list_tags_for_resource(resourceArn=scope_arn)["tags"]
    assert "sim2real-env" not in tags_before, f"expected no sim2real-env tag before TagResource, got tags={tags_before!r}"

    nfm.tag_resource(resourceArn=scope_arn, tags={"sim2real-env": "behavioral"})
    tags_after_tag = nfm.list_tags_for_resource(resourceArn=scope_arn)["tags"]
    assert tags_after_tag.get("sim2real-env") == "behavioral", (
        f"expected sim2real-env=behavioral after TagResource, got tags={tags_after_tag!r}"
    )

    nfm.untag_resource(resourceArn=scope_arn, tagKeys=["sim2real-env"])
    tags_after_untag = nfm.list_tags_for_resource(resourceArn=scope_arn)["tags"]
    assert "sim2real-env" not in tags_after_untag, (
        f"expected sim2real-env removed after UntagResource, got tags={tags_after_untag!r}"
    )


def _acquire_scope(ctx, nfm, target: dict) -> dict:
    """Acquire a scope. NetworkFlowMonitor allows only one scope per account/Region, so if one
    already exists (created by another check) it is reused."""
    try:
        resp = nfm.create_scope(targets=[target])
        scope_id, scope_arn = resp["scopeId"], resp["scopeArn"]
        ctx.on_cleanup(lambda: _delete_scope_and_wait(nfm, scope_id))
    except ClientError as err:
        if err.response["Error"]["Code"] != "ServiceQuotaExceededException":
            raise
        existing = nfm.list_scopes().get("scopes", [])
        assert existing, f"ServiceQuotaExceededException but ListScopes returned no existing scope, got scopes={existing!r}"
        scope_id = existing[0]["scopeId"]
        scope_arn = nfm.get_scope(scopeId=scope_id)["scopeArn"]
    _wait_scope_succeeded(nfm, scope_id)
    return {"scopeId": scope_id, "scopeArn": scope_arn}


def _delete_scope_and_wait(nfm, scope_id: str, timeout_s: float = 300.0, interval_s: float = 10.0) -> None:
    try:
        nfm.delete_scope(scopeId=scope_id)
    except ClientError as err:
        if err.response["Error"]["Code"] in ("ResourceNotFoundException", "ConflictException", "ValidationException"):
            return
        raise
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            status = nfm.get_scope(scopeId=scope_id)["status"]
        except ClientError as err:
            if err.response["Error"]["Code"] == "ResourceNotFoundException":
                return
            raise
        if status == "DEACTIVATED":
            return
        time.sleep(interval_s)
    raise AssertionError(f"scope {scope_id} did not fully deactivate within {timeout_s}s")


def _wait_scope_succeeded(nfm, scope_id: str, timeout_s: float = 900.0) -> None:
    final = _poll_until(
        lambda: nfm.get_scope(scopeId=scope_id)["status"],
        lambda s: s in ("SUCCEEDED", "FAILED"),
        timeout_s=timeout_s,
        interval_s=5.0,
    )
    assert final == "SUCCEEDED", f"expected scope {scope_id} to settle SUCCEEDED, got status={final!r}"


def _poll_until(probe, predicate, timeout_s=180.0, interval_s=5.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last={last!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

