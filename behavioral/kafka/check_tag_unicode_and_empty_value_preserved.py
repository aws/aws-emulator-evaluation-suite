"""tag-unicode-and-empty-value-preserved."""
from __future__ import annotations

import time
from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "tag-unicode-and-empty-value-preserved"
GROUP = "tags"
SERVICES = ["kafka"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Unicode tag keys/values and an explicit empty-string value survive TagResource and
    ListTagsForResource unchanged on a cluster, and an empty value is distinct from an unset key."""
    kafka_version = _pick_active_kafka_version(ctx)
    # kafka:TagResource accepts only cluster and vpc-connection ARNs; Configuration/Replicator
    # ARNs are rejected ("Invalid input resource arn"), so the check tags a cluster.
    cluster_arn = _create_basic_cluster(ctx, kafka_version)
    kafka = ctx.client("kafka")

    unicode_key = "\u00dcnic\u00f6d\u00e9-Kl\u00fcb"
    unicode_value = "\u4e16\u754c-\u041c\u0438\u0440"
    empty_value_key = "EmptyValueTag"

    # Registered before the mutation so a failing assertion still cleans up; untagging an
    # already-removed key is a no-op, so it is safe after the explicit untag below.
    ctx.on_cleanup(
        lambda: kafka.untag_resource(
            ResourceArn=cluster_arn, TagKeys=[unicode_key, empty_value_key]
        )
    )

    kafka.tag_resource(
        ResourceArn=cluster_arn,
        Tags={
            unicode_key: unicode_value,
            empty_value_key: "",
        },
    )

    tags = kafka.list_tags_for_resource(ResourceArn=cluster_arn)["Tags"]
    assert tags[unicode_key] == unicode_value, "unicode tag key/value was not preserved exactly"
    assert empty_value_key in tags, "a tag with an explicit empty string value went missing entirely"
    assert tags[empty_value_key] == "", "explicit empty tag value was not preserved as empty"
    assert "NeverSetTag" not in tags, "a tag key that was never set appeared in ListTagsForResource"

    kafka.untag_resource(ResourceArn=cluster_arn, TagKeys=[unicode_key, empty_value_key])
    after = kafka.list_tags_for_resource(ResourceArn=cluster_arn)["Tags"]
    assert unicode_key not in after, "unicode tag key survived UntagResource"
    assert empty_value_key not in after, "explicit empty-value tag survived UntagResource"


def _default_client_subnets(ctx, count: int = 2) -> list[str]:
    """Subnets of the run's shared network (ctx.network()) in count distinct AZs."""
    net = ctx.network()
    if len(net.subnets) < count:
        raise AssertionError(f"the shared network has {len(net.subnets)} availability-zone subnets, need {count}")
    return net.subnet_ids[:count]


def _poll_cluster_state(
    ctx, cluster_arn: str, desired: set[str], timeout_s: float = 1800.0, interval_s: float = 20.0
) -> dict[str, Any]:
    kafka = ctx.client("kafka")
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        info = kafka.describe_cluster(ClusterArn=cluster_arn)["ClusterInfo"]
        last = info["State"]
        if last in desired:
            return info
        if last == "FAILED":
            raise AssertionError(f"cluster entered FAILED state: {info.get('StateInfo')}")
        time.sleep(interval_s)
    raise AssertionError(f"cluster did not reach {desired} within {timeout_s}s (last state={last})")


def _create_basic_cluster(ctx, kafka_version: str, **extra: Any) -> str:
    kafka = ctx.client("kafka")
    subnets = _default_client_subnets(ctx, 2)
    name = ctx.unique_name("sim2real-behav-")
    kwargs: dict[str, Any] = dict(
        ClusterName=name,
        KafkaVersion=kafka_version,
        NumberOfBrokerNodes=len(subnets),
        BrokerNodeGroupInfo={
            "InstanceType": "kafka.t3.small",
            "ClientSubnets": subnets,
            "StorageInfo": {"EbsStorageInfo": {"VolumeSize": 100}},
        },
        Tags={"sim2real:managed": "true"},
    )
    kwargs.update(extra)
    resp = kafka.create_cluster(**kwargs)
    arn = resp["ClusterArn"]
    ctx.on_cleanup(lambda: _delete_cluster_when_settled(kafka, arn))
    _poll_cluster_state(ctx, arn, {"ACTIVE"})
    return arn


def _pick_active_kafka_version(ctx) -> str:
    # Standard brokers accept 3.9.x; they reject older versions and the Express-only 4.2.x.
    status = {v["Version"]: v.get("Status") for v in ctx.client("kafka").list_kafka_versions().get("KafkaVersions", [])}
    if status.get("3.9.x") != "ACTIVE":
        raise AssertionError(f"Kafka 3.9.x is not ACTIVE in ListKafkaVersions: {sorted(status)}")
    return "3.9.x"


def _delete_cluster_when_settled(msk, arn, timeout_s=2400.0, interval_s=30.0):
    """DeleteCluster refuses a cluster that is CREATING or UPDATING, so wait for ACTIVE or FAILED first."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            state = msk.describe_cluster_v2(ClusterArn=arn)["ClusterInfo"]["State"]
            if state == "DELETING":
                return
            if state in ("ACTIVE", "FAILED"):
                msk.delete_cluster(ClusterArn=arn)
                return
        except ClientError as e:
            if e.response["Error"]["Code"] == "NotFoundException":
                return
            raise
        if time.monotonic() >= deadline:
            raise AssertionError(f"cluster {arn} still {state} after {timeout_s:.0f}s; it cannot be deleted")
        time.sleep(interval_s)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
