"""scope-tags-set-at-creation."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "scope-tags-set-at-creation"
GROUP = "tags"
SERVICES = ["networkflowmonitor"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control", "resource:account-singleton:networkflowmonitor-scope")
def run(ctx) -> None:
    """Tags passed to CreateScope come back in its response and on GetScope and ListTagsForResource;
    when the Region's one scope already exists, TagResource sets them on it and both reads show them."""
    nfm = ctx.client("networkflowmonitor")
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    tags = {"sim2real-owner": "behavioral-suite"}

    target = {"targetIdentifier": {"targetId": {"accountId": account_id}, "targetType": "ACCOUNT"}, "region": ctx.region}
    try:
        created = nfm.create_scope(targets=[target], tags=tags)
        scope_id = created["scopeId"]
        scope_arn = created["scopeArn"]
        ctx.on_cleanup(lambda: _delete_scope_and_wait(nfm, scope_id))
        assert created["tags"] == tags, f"expected CreateScope response tags {tags!r}, got {created.get('tags')!r}"
    except ClientError as err:
        if err.response["Error"]["Code"] != "ServiceQuotaExceededException":
            raise
        existing = nfm.list_scopes().get("scopes", [])
        assert existing, "ServiceQuotaExceededException but no existing scope found via ListScopes"
        scope_id = existing[0]["scopeId"]
        status = nfm.get_scope(scopeId=scope_id)["status"]
        if status in ("DEACTIVATED", "DEACTIVATING"):
            try:
                nfm.update_scope(scopeId=scope_id, resourcesToAdd=[target])
            except ClientError as err2:
                if err2.response["Error"]["Code"] not in ("ConflictException", "ValidationException"):
                    raise
        _wait_scope_succeeded(nfm, scope_id)
        scope_arn = nfm.get_scope(scopeId=scope_id)["scopeArn"]
        nfm.tag_resource(resourceArn=scope_arn, tags=tags)

    fetched = nfm.get_scope(scopeId=scope_id)
    assert tags.items() <= fetched["tags"].items(), (
        f"expected {tags!r} to be a subset of GetScope tags {fetched.get('tags')!r}"
    )

    listed = nfm.list_tags_for_resource(resourceArn=scope_arn)["tags"]
    assert tags.items() <= listed.items(), (
        f"expected {tags!r} to be a subset of ListTagsForResource tags {listed!r}"
    )


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


def _wait_scope_succeeded(nfm, scope_id: str, timeout_s: float = 600.0) -> None:
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = nfm.get_scope(scopeId=scope_id)["status"]
        if last in ("SUCCEEDED", "FAILED"):
            break
        time.sleep(5.0)
    else:
        raise AssertionError(f"scope {scope_id} did not settle within {timeout_s}s; last={last!r}")
    assert last == "SUCCEEDED", f"expected scope {scope_id} status SUCCEEDED, got {last!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)


