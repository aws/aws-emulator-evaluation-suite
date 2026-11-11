"""tag-gateway-resource-roundtrip-list-and-untag."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "tag-gateway-resource-roundtrip-list-and-untag"
GROUP = "tagging"
SERVICES = ["iotsitewise"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """TagResource/UntagResource round-trip cleanly through ListTagsForResource on a Gateway ARN
    (a distinct resource type from asset models), proving tagging isn't hardcoded to one resource
    kind."""
    sw = ctx.client("iotsitewise")
    core_device_thing_name = ctx.unique_name("sim2real-sw-core-").replace("-", "_")
    resp = sw.create_gateway(
        gatewayName=ctx.unique_name("sim2real-sw-gw-"),
        gatewayPlatform={"greengrassV2": {"coreDeviceThingName": core_device_thing_name}},
    )
    gateway_id = resp["gatewayId"]
    arn = resp["gatewayArn"]

    def _cleanup():
        try:
            sw.delete_gateway(gatewayId=gateway_id)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise

    ctx.on_cleanup(_cleanup)

    sw.tag_resource(resourceArn=arn, tags={"env": "sim2real", "fleet": "edge"})
    tags = sw.list_tags_for_resource(resourceArn=arn)["tags"]
    assert tags == {"env": "sim2real", "fleet": "edge"}, (
        f"expected both tags visible on the gateway via an independent ListTagsForResource, got {tags!r}"
    )

    sw.untag_resource(resourceArn=arn, tagKeys=["fleet"])
    tags_after = sw.list_tags_for_resource(resourceArn=arn)["tags"]
    assert tags_after == {"env": "sim2real"}, (
        f"expected only 'env' to remain after UntagResource(['fleet']), got {tags_after!r}"
    )


def _poll_until(probe, predicate, *, timeout_s=120.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
