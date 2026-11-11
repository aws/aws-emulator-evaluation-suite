"""tag-untag-round-trip."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "tag-untag-round-trip"
GROUP = "control-plane-depth"
SERVICES = ["keyspaces"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """TagResource/UntagResource/ListTagsForResource form a consistent round trip on a keyspace."""
    kc = ctx.client("keyspaces")
    ks_name = _kname(ctx, "sim2real_behav_ks")
    arn = kc.create_keyspace(keyspaceName=ks_name)["resourceArn"]
    ctx.on_cleanup(lambda: _ignore_not_found(lambda: kc.delete_keyspace(keyspaceName=ks_name)))

    _tag_resource_when_ready(
        kc, arn, [{"key": "env", "value": "sim2real"}, {"key": "owner", "value": "behav"}]
    )
    tags = {t["key"]: t["value"] for t in kc.list_tags_for_resource(resourceArn=arn)["tags"]}
    assert tags.get("env") == "sim2real" and tags.get("owner") == "behav", tags

    kc.untag_resource(resourceArn=arn, tags=[{"key": "owner", "value": "behav"}])
    tags_after = {t["key"]: t["value"] for t in kc.list_tags_for_resource(resourceArn=arn)["tags"]}
    assert "owner" not in tags_after, tags_after
    assert tags_after.get("env") == "sim2real", tags_after


def _kname(ctx, prefix: str) -> str:
    return ctx.unique_name(prefix + "-").replace("-", "_")[:48]


def _ignore_not_found(fn) -> None:
    from botocore.exceptions import ClientError
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _tag_resource_when_ready(kc, arn: str, tags: list, timeout_s: float = 90.0) -> None:
    """TagResource right after CreateKeyspace can transiently 404 until the keyspace is
    visible; retry only that specific transient condition."""
    import time
    from botocore.exceptions import ClientError
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            kc.tag_resource(resourceArn=arn, tags=tags)
            return
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException" or time.monotonic() > deadline:
                raise
            time.sleep(2.0)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
