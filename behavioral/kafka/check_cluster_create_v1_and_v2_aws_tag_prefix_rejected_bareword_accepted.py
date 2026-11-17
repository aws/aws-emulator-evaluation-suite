"""cluster-create-v1-and-v2-aws-tag-prefix-rejected-bareword-accepted."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cluster-create-v1-and-v2-aws-tag-prefix-rejected-bareword-accepted"
GROUP = "overly-permissive"
SERVICES = ["kafka"]

_INSTANCE_TYPE = "kafka.m5.large"
_KAFKA_VERSION = "3.9.x"
_AWS_PREFIX_REJECTED = (
    "BadRequestException",
    "Invalid tag key. Customers cannot set tag keys starting with aws: (case insensitive)",
)


def _error(fn):
    """Call fn(); return the (Error.Code, Error.Message) of the ClientError it must raise."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


def expect_error(fn, code, message):
    got_code, got_message = _error(fn)
    assert got_code == code, f"expected code {code!r}, got {got_code!r}: {got_message!r}"
    assert got_message == message, f"expected message {message!r}, got {got_message!r}"


def _broker_node_group_info(subnet_ids, sg_id):
    return {
        "InstanceType": _INSTANCE_TYPE,
        "ClientSubnets": subnet_ids,
        "SecurityGroups": [sg_id],
        "StorageInfo": {"EbsStorageInfo": {"VolumeSize": 100}},
    }


def _wait_until_settled(msk, arn, timeout_s=2700.0, interval_s=20.0):
    """Poll until the cluster leaves CREATING, here in the run rather than in teardown, so the
    teardown's DeleteCluster (refused while CREATING) does not have to wait out its own budget."""
    deadline = time.monotonic() + timeout_s
    while True:
        state = msk.describe_cluster_v2(ClusterArn=arn)["ClusterInfo"]["State"]
        if state != "CREATING":
            return state
        if time.monotonic() >= deadline:
            raise AssertionError(f"cluster {arn} still CREATING after {timeout_s:.0f}s")
        time.sleep(interval_s)


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateCluster and CreateClusterV2 each refuse a Tags key whose prefix is "aws:", in any
    case, provisioning nothing; a key that merely starts with the letters "aws" but carries no
    colon is an ordinary tag, accepted and stored by CreateClusterV2 exactly as sent."""
    msk = ctx.client("kafka")
    net = ctx.network()
    subnet_ids = net.subnet_ids[:2]
    sg_id = net.security_group_id

    v1_name = ctx.unique_name("sim2real-behav-v1tag-")
    expect_error(
        lambda: msk.create_cluster(
            ClusterName=v1_name,
            BrokerNodeGroupInfo=_broker_node_group_info(subnet_ids, sg_id),
            KafkaVersion=_KAFKA_VERSION,
            NumberOfBrokerNodes=2,
            Tags={"aws:owner": "nope"},
        ),
        *_AWS_PREFIX_REJECTED,
    )
    v1_listed = msk.list_clusters(ClusterNameFilter=v1_name).get("ClusterInfoList", [])
    assert v1_listed == [], f"CreateCluster was rejected but still provisioned a cluster: {v1_listed!r}"

    v2_name = ctx.unique_name("sim2real-behav-v2tag-")
    expect_error(
        lambda: msk.create_cluster_v2(
            ClusterName=v2_name,
            Provisioned={
                "BrokerNodeGroupInfo": _broker_node_group_info(subnet_ids, sg_id),
                "KafkaVersion": _KAFKA_VERSION,
                "NumberOfBrokerNodes": 2,
            },
            Tags={"AWS:Owner": "nope"},
        ),
        *_AWS_PREFIX_REJECTED,
    )
    v2_listed = []
    for page in msk.get_paginator("list_clusters_v2").paginate(ClusterNameFilter=v2_name):
        v2_listed.extend(page.get("ClusterInfoList", []))
    assert v2_listed == [], f"CreateClusterV2 was rejected but still provisioned a cluster: {v2_listed!r}"

    ok_name = ctx.unique_name("sim2real-behav-v2tagok-")
    resp = msk.create_cluster_v2(
        ClusterName=ok_name,
        Provisioned={
            "BrokerNodeGroupInfo": _broker_node_group_info(subnet_ids, sg_id),
            "KafkaVersion": _KAFKA_VERSION,
            "NumberOfBrokerNodes": 2,
        },
        Tags={"awsteam": "nope"},
    )
    ok_arn = resp["ClusterArn"]
    ctx.on_cleanup(lambda: msk.delete_cluster(ClusterArn=ok_arn))
    assert resp["ClusterName"] == ok_name, resp

    stored_tags = msk.list_tags_for_resource(ResourceArn=ok_arn)["Tags"]
    assert stored_tags == {"awsteam": "nope"}, stored_tags

    _wait_until_settled(msk, ok_arn)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
