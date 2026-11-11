"""tag-and-untag-resource-round-trip."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "tag-and-untag-resource-round-trip"
GROUP = "data-plane"
SERVICES = ["dsql"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """TagResource adds tags visible via ListTagsForResource; UntagResource removes exactly the requested keys."""
    dsql = ctx.client("dsql")
    created = dsql.create_cluster(deletionProtectionEnabled=False)
    identifier = created["identifier"]
    arn = created["arn"]
    ctx.on_cleanup(lambda: _delete_cluster(ctx, identifier))
    final_status = _poll_until(
        lambda: dsql.get_cluster(identifier=identifier)["status"],
        lambda s: s in ("ACTIVE", "FAILED"),
        timeout_s=300.0,
        interval_s=5.0,
    )
    assert final_status == "ACTIVE", f"cluster reached terminal status {final_status!r} instead of ACTIVE"

    dsql.tag_resource(resourceArn=arn, tags={"sim2real-a": "1", "sim2real-b": "2"})
    tags = dsql.list_tags_for_resource(resourceArn=arn)["tags"]
    assert tags.get("sim2real-a") == "1", f"expected sim2real-a=1 after TagResource, got {tags.get('sim2real-a')!r}"
    assert tags.get("sim2real-b") == "2", f"expected sim2real-b=2 after TagResource, got {tags.get('sim2real-b')!r}"

    dsql.untag_resource(resourceArn=arn, tagKeys=["sim2real-a"])
    tags_after = dsql.list_tags_for_resource(resourceArn=arn)["tags"]
    assert "sim2real-a" not in tags_after, f"UntagResource must remove the requested key, still present: {tags_after}"
    assert tags_after.get("sim2real-b") == "2", (
        f"expected untouched tag sim2real-b=2 to remain, got {tags_after.get('sim2real-b')!r}"
    )


def _poll_until(probe, predicate, *, timeout_s=120.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last={last!r}")


def _delete_cluster(ctx, identifier):
    from botocore.exceptions import ClientError

    dsql = ctx.client("dsql")
    try:
        dsql.update_cluster(identifier=identifier, deletionProtectionEnabled=False)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise
    try:
        dsql.delete_cluster(identifier=identifier)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
