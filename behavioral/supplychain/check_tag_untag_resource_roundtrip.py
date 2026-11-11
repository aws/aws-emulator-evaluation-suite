"""tag-untag-resource-roundtrip."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "tag-untag-resource-roundtrip"
GROUP = "data-plane"
SERVICES = ["supplychain"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """TagResource adds tags visible through ListTagsForResource, and UntagResource removes
    exactly the requested keys while leaving the others in place."""
    # AWS Supply Chain rejects CreateInstance outright in the harness's default region
    # (ValidationException: "... is not supported in us-west-2"); it is only available in
    # us-east-1 (and eu-west-1). Transport-only pin, not an assertion fork.
    region = "us-east-1"
    sc = ctx.client("supplychain", region=region)
    instance_id = _create_active_instance(ctx, sc)
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    instance_arn = f"arn:aws:scn:{region}:{account_id}:instance/{instance_id}"

    sc.tag_resource(resourceArn=instance_arn, tags={"team": "sim2real", "keep": "yes"})

    tags_after_add = sc.list_tags_for_resource(resourceArn=instance_arn)["tags"]
    assert tags_after_add.get("team") == "sim2real", (
        f"expected tag 'team'='sim2real' after TagResource, got {tags_after_add!r}"
    )
    assert tags_after_add.get("keep") == "yes", (
        f"expected tag 'keep'='yes' after TagResource, got {tags_after_add!r}"
    )

    sc.untag_resource(resourceArn=instance_arn, tagKeys=["team"])
    tags_after_remove = sc.list_tags_for_resource(resourceArn=instance_arn)["tags"]
    assert "team" not in tags_after_remove, (
        f"expected 'team' removed by UntagResource, still present in {tags_after_remove!r}"
    )
    assert tags_after_remove.get("keep") == "yes", (
        f"expected untouched tag 'keep'='yes' to survive UntagResource, got {tags_after_remove!r}"
    )


def _poll_until(probe, predicate, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last={last!r}")


def _create_active_instance(ctx, sc):
    name = ctx.unique_name("sim2real-sc-")
    instance = sc.create_instance(
        instanceName=name, instanceDescription="sim2real behavioral check"
    )["instance"]
    instance_id = instance["instanceId"]

    def _cleanup():
        try:
            sc.delete_instance(instanceId=instance_id)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise

    ctx.on_cleanup(_cleanup)
    result = _poll_until(
        lambda: sc.get_instance(instanceId=instance_id)["instance"],
        lambda inst: inst["state"] in ("Active", "CreateFailed"),
        timeout_s=1200.0,
        interval_s=15.0,
    )
    if result["state"] != "Active":
        raise AssertionError(f"instance did not reach Active state: {result}")
    return instance_id


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
