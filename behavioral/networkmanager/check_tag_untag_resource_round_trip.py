"""tag-untag-resource-round-trip."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "tag-untag-resource-round-trip"
GROUP = "tagging"
SERVICES = ["networkmanager"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """TagResource adds tags visible via ListTagsForResource; UntagResource removes exactly one."""
    nm = ctx.client("networkmanager")
    gn_id, gn_arn = _create_global_network(ctx, nm)

    nm.tag_resource(
        ResourceArn=gn_arn,
        Tags=[{"Key": "sim2real-team", "Value": "networking"}, {"Key": "sim2real-tier", "Value": "core"}],
    )
    tags = {t["Key"]: t["Value"] for t in nm.list_tags_for_resource(ResourceArn=gn_arn)["TagList"]}
    assert tags.get("sim2real-team") == "networking", f"expected sim2real-team=networking, got {tags!r}"
    assert tags.get("sim2real-tier") == "core", f"expected sim2real-tier=core, got {tags!r}"

    nm.untag_resource(ResourceArn=gn_arn, TagKeys=["sim2real-team"])
    tags_after = {t["Key"]: t["Value"] for t in nm.list_tags_for_resource(ResourceArn=gn_arn)["TagList"]}
    assert "sim2real-team" not in tags_after, f"expected sim2real-team removed, got {tags_after!r}"
    assert tags_after.get("sim2real-tier") == "core", f"expected sim2real-tier=core to survive untag, got {tags_after!r}"


def _safe_call(fn):
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _global_network_state(nm, gn_id):
    """Return the global network's State, or "GONE" once AWS no longer lists it."""
    try:
        networks = nm.describe_global_networks(GlobalNetworkIds=[gn_id])["GlobalNetworks"]
    except ClientError as e:
        if e.response["Error"]["Code"] == "ResourceNotFoundException":
            return "GONE"
        raise
    return networks[0]["State"] if networks else "GONE"


def _poll_until(probe, predicate, timeout_s=90.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last={last!r}")


def _create_global_network(ctx, nm):
    gn = nm.create_global_network(Description=ctx.unique_name("sim2real-gn-"))["GlobalNetwork"]
    gn_id = gn["GlobalNetworkId"]
    gn_arn = gn["GlobalNetworkArn"]
    ctx.on_cleanup(lambda: _delete_global_network_and_wait(nm, gn_id))
    _poll_until(
        lambda: nm.describe_global_networks(GlobalNetworkIds=[gn_id])["GlobalNetworks"][0]["State"],
        lambda s: s == "AVAILABLE",
    )
    return gn_id, gn_arn


def _delete_global_network_and_wait(nm, gn_id):
    _safe_call(lambda: nm.delete_global_network(GlobalNetworkId=gn_id))
    _poll_until(
        lambda: _global_network_state(nm, gn_id),
        lambda s: s == "GONE",
        timeout_s=150.0,
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
