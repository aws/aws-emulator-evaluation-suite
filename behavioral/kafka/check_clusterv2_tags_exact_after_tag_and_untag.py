"""clusterv2-tags-exact-after-tag-and-untag."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "clusterv2-tags-exact-after-tag-and-untag"
GROUP = "tags"
SERVICES = ["kafka"]


def _cluster_subnets(ctx, count=2):
    """Up to `count` of the shared network's subnets, one per distinct availability zone."""
    net = ctx.network()
    zones = sorted(net.availability_zones)
    assert len(zones) >= count, (
        f"the shared network only spans {len(zones)} availability zone(s), need {count}"
    )
    return net.vpc_id, [net.subnets[az] for az in zones[:count]], net.security_group_id


def _delete_when_deletable(msk, arn, timeout_s=1200.0, interval_s=15.0):
    """DeleteCluster refuses a cluster still CREATING; wait for a settled state first."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            state = msk.describe_cluster_v2(ClusterArn=arn)["ClusterInfo"]["State"]
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "NotFoundException":
                return
            raise
        if state in ("ACTIVE", "FAILED"):
            msk.delete_cluster(ClusterArn=arn)
            return
        if state == "DELETING":
            return
        if time.monotonic() >= deadline:
            raise AssertionError(f"cluster {arn} still {state!r} after {timeout_s:.0f}s; cannot delete it")
        time.sleep(interval_s)


def _wait_active(msk, arn, timeout_s=1200.0, interval_s=15.0):
    deadline = time.monotonic() + timeout_s
    info = None
    while time.monotonic() < deadline:
        info = msk.describe_cluster_v2(ClusterArn=arn)["ClusterInfo"]
        state = info.get("State")
        if state in ("ACTIVE", "FAILED"):
            if state != "ACTIVE":
                raise AssertionError(f"cluster {arn} reached {state!r} instead of 'ACTIVE'")
            return info
        time.sleep(interval_s)
    raise AssertionError(f"cluster {arn} did not settle within {timeout_s:.0f}s; last state {info!r}")


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DescribeClusterV2 ClusterInfo.Tags equals the create-time tags once ACTIVE, and after a
    TagResource add and an UntagResource remove it equals ListTagsForResource exactly, no more.
    """
    msk = ctx.client("kafka")
    _vpc_id, subnet_ids, sg_id = _cluster_subnets(ctx, count=2)
    name = ctx.unique_name("sim2real-behav-clustertags-")

    create_time_tags = {"component": "cluster-tags-check", "retention": "short-lived"}
    resp = msk.create_cluster_v2(
        ClusterName=name,
        Serverless={
            "VpcConfigs": [{"SubnetIds": subnet_ids, "SecurityGroupIds": [sg_id] if sg_id else []}],
            "ClientAuthentication": {"Sasl": {"Iam": {"Enabled": True}}},
        },
        Tags=create_time_tags,
    )
    arn = resp["ClusterArn"]
    ctx.on_cleanup(lambda: _delete_when_deletable(msk, arn))

    info = _wait_active(msk, arn)
    assert info["Tags"] == create_time_tags, (
        f"ClusterInfo.Tags once ACTIVE was {info['Tags']!r}, expected exactly {create_time_tags!r}"
    )

    msk.tag_resource(ResourceArn=arn, Tags={"owner": "fidelity-check"})
    msk.untag_resource(ResourceArn=arn, TagKeys=["retention"])

    expected_tags = {"component": "cluster-tags-check", "owner": "fidelity-check"}
    described_tags = msk.describe_cluster_v2(ClusterArn=arn)["ClusterInfo"]["Tags"]
    listed_tags = msk.list_tags_for_resource(ResourceArn=arn)["Tags"]
    assert described_tags == expected_tags, (
        f"DescribeClusterV2 Tags after tag/untag was {described_tags!r}, expected {expected_tags!r}"
    )
    assert described_tags == listed_tags, (
        f"DescribeClusterV2 Tags {described_tags!r} disagrees with ListTagsForResource {listed_tags!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
