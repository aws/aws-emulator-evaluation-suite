"""cluster-policy-json-unicode-round-trip."""
from __future__ import annotations

import json
import time
from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "cluster-policy-json-unicode-round-trip"
GROUP = "state-machine"
SERVICES = ["kafka"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """PutClusterPolicy accepts a policy with unicode, escaped tab/newline values and whitespace between
    tokens, and GetClusterPolicy returns it as compact JSON with every value, escape and key order
    preserved."""
    kafka_version = _pick_active_kafka_version(ctx)
    cluster_arn = _create_basic_cluster(ctx, kafka_version)

    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]
    kafka = ctx.client("kafka")

    policy_doc = (
        "{\n"
        '\t"Version": "2012-10-17",\n'
        '\t"Statement": [\n'
        "\t\t{\n"
        '\t\t\t"Sid": "UnicodeAccess",\n'
        '\t\t\t"Effect": "Allow",\n'
        f'\t\t\t"Principal": {{"AWS": "arn:aws:iam::{account_id}:root"}},\n'
        '\t\t\t"Action": "kafka:GetBootstrapBrokers",\n'
        f'\t\t\t"Resource": "{cluster_arn}",\n'
        '\t\t\t"Condition": {"StringLike": {"aws:userid": "h\u00e9llo-\u4e16\u754c-\u0394\u03bf\u03ba\u03b9\u03bc\u03ae  test\\t\\n"}}\n'
        "\t\t}\n"
        "\t]\n"
        "}"
    )

    kafka.put_cluster_policy(ClusterArn=cluster_arn, Policy=policy_doc)
    ctx.on_cleanup(lambda: kafka.delete_cluster_policy(ClusterArn=cluster_arn))

    resp = kafka.get_cluster_policy(ClusterArn=cluster_arn)
    expected = json.dumps(json.loads(policy_doc), separators=(",", ":"), ensure_ascii=False)
    assert resp["Policy"] == expected, (
        f"GetClusterPolicy did not return the policy canonicalized as compact JSON with "
        f"values, unicode content, escape sequences and key order preserved: "
        f"expected {expected!r}, got {resp['Policy']!r}"
    )


def _default_client_subnets(ctx, count: int = 2) -> list[str]:
    ec2 = ctx.client("ec2")
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if not vpcs:
        raise AssertionError("no shared network available to place MSK broker subnets")
    vpc_id = vpcs[0]["VpcId"]
    subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}])["Subnets"]
    by_az: dict[str, str] = {}
    for s in subnets:
        by_az.setdefault(s["AvailabilityZone"], s["SubnetId"])
    subnet_ids = list(by_az.values())[:count]
    if len(subnet_ids) < count:
        raise AssertionError(f"shared network has fewer than {count} usable availability zones")
    return subnet_ids


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
