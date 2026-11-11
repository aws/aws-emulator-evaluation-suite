"""compatible-kafka-versions-matches-real-upgrade-path."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "compatible-kafka-versions-matches-real-upgrade-path"
GROUP = "data-plane"
SERVICES = ["kafka"]

_CLUSTER_WAIT_TIMEOUT_S = 1800
_VERSION_UPGRADE_SETTLE_TIMEOUT_S = 5400


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetCompatibleKafkaVersions lists exactly the targets that UpdateClusterKafkaVersion will
    accept for this cluster's current Kafka version -- and rejects targets it doesn't list."""
    cluster_arn = _create_provisioned_cluster(ctx, version_pick="oldest")
    kafka = ctx.client("kafka")

    initial_info = kafka.describe_cluster(ClusterArn=cluster_arn)["ClusterInfo"]
    initial_version = initial_info["CurrentBrokerSoftwareInfo"]["KafkaVersion"]

    compatible = kafka.get_compatible_kafka_versions(ClusterArn=cluster_arn)["CompatibleKafkaVersions"]
    targets: list[str] = []
    for entry in compatible:
        if entry.get("SourceVersion") == initial_version:
            targets = entry.get("TargetVersions") or []
            break
    if not targets:
        raise AssertionError(
            f"GetCompatibleKafkaVersions reports no upgrade target for KafkaVersion {initial_version!r} in "
            "this account/region, so the acceptance path cannot be exercised"
        )
    target_version = targets[0]

    current_version_token = kafka.describe_cluster(ClusterArn=cluster_arn)["ClusterInfo"]["CurrentVersion"]

    # Negative: a target NOT present in GetCompatibleKafkaVersions must be rejected.
    bogus_version = "0.0.0-sim2real-not-a-real-kafka-version"
    assert bogus_version not in targets and bogus_version != initial_version
    code = _error_code(
        lambda: kafka.update_cluster_kafka_version(
            ClusterArn=cluster_arn, CurrentVersion=current_version_token, TargetKafkaVersion=bogus_version
        )
    )
    assert code == "BadRequestException"
    unchanged = kafka.describe_cluster(ClusterArn=cluster_arn)["ClusterInfo"]
    assert unchanged["State"] == "ACTIVE"
    assert unchanged["CurrentBrokerSoftwareInfo"]["KafkaVersion"] == initial_version

    # Positive: a target GetCompatibleKafkaVersions DID list must be accepted, kick off a real
    # rolling upgrade (observable as the documented ACTIVE -> UPDATING transition), and land on
    # the target version -- not merely start one. The settle-back-to-ACTIVE wait happens HERE, in
    # the check's own body, rather than in ctx.on_cleanup: a version upgrade is a long rolling
    # restart that can outlive the cleanup budget, so waiting it out as cleanup would abandon
    # the cluster mid-UPDATING with the delete never attempted.
    accepted = kafka.update_cluster_kafka_version(
        ClusterArn=cluster_arn, CurrentVersion=current_version_token, TargetKafkaVersion=target_version
    )
    assert accepted["ClusterOperationArn"]
    updating = _wait_for_cluster_state(ctx, cluster_arn, "UPDATING", timeout_s=300)
    assert updating["State"] == "UPDATING"

    settled = _wait_for_cluster_state(ctx, cluster_arn, "ACTIVE", timeout_s=_VERSION_UPGRADE_SETTLE_TIMEOUT_S)
    assert settled["State"] == "ACTIVE"
    settled_version = settled["CurrentBrokerSoftwareInfo"]["KafkaVersion"]
    assert settled_version == target_version, (
        f"upgrade settled to State=ACTIVE but KafkaVersion is {settled_version!r}, expected the "
        f"requested TargetKafkaVersion {target_version!r}"
    )


# ===== helpers =====
def _error_code(fn):
    try:
        fn()
        return None
    except ClientError as e:
        return e.response["Error"]["Code"]


def _default_vpc_subnets_and_sg(ctx):
    ec2 = ctx.client("ec2")
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if not vpcs:
        raise AssertionError("no shared network available in this account/region to provision an MSK broker cluster")
    vpc_id = vpcs[0]["VpcId"]
    subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}])["Subnets"]
    by_az = {}
    for s in subnets:
        by_az.setdefault(s["AvailabilityZone"], s["SubnetId"])
    if len(by_az) < 2:
        raise AssertionError("shared network lacks subnets in at least 2 AZs required to place MSK broker nodes")
    subnet_ids = list(by_az.values())[:2]
    sgs = ec2.describe_security_groups(
        Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "group-name", "Values": ["default"]}]
    )["SecurityGroups"]
    sg_id = sgs[0]["GroupId"]
    return vpc_id, subnet_ids, sg_id


def _active_kafka_version(ctx, pick="latest"):
    kafka = ctx.client("kafka")
    versions = kafka.list_kafka_versions().get("KafkaVersions", [])
    # Kafka 4.2.x is available on Express brokers only; these checks create Standard brokers.
    active = sorted(
        v["Version"] for v in versions if v.get("Status") == "ACTIVE" and not v["Version"].startswith("4.2.")
    )
    if not active:
        raise AssertionError("no ACTIVE Kafka version reported by ListKafkaVersions")
    return active[0] if pick == "oldest" else active[-1]


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _wait_for_cluster_state(ctx, arn, target_state, timeout_s=_CLUSTER_WAIT_TIMEOUT_S):
    kafka = ctx.client("kafka")
    timeout_s = _budget_s(ctx, timeout_s)
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        info = kafka.describe_cluster(ClusterArn=arn)["ClusterInfo"]
        last = info["State"]
        if last == target_state:
            return info
        if last == "FAILED":
            raise AssertionError(f"cluster {arn} entered FAILED state while waiting for {target_state}")
        time.sleep(2)
    if _budget_spent(ctx):
        raise TimeoutError(f"cluster {arn} reaching {target_state}: the run budget ended first; not graded")
    raise AssertionError(f"cluster {arn} did not reach {target_state} within {timeout_s:.0f}s (last observed: {last})")


def _delete_cluster_and_wait(ctx, arn, timeout_s=_CLUSTER_WAIT_TIMEOUT_S):
    kafka = ctx.client("kafka")
    try:
        kafka.delete_cluster(ClusterArn=arn)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NotFoundException":
            raise
        return
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            kafka.describe_cluster(ClusterArn=arn)
        except ClientError as e:
            if e.response["Error"]["Code"] == "NotFoundException":
                return
            raise
        time.sleep(2)
    raise AssertionError(f"cluster {arn} was not deleted within {timeout_s}s")


def _create_provisioned_cluster(
    ctx, *, client_authentication=None, connectivity_info=None, kafka_version=None, version_pick="latest"
):
    kafka = ctx.client("kafka")
    _vpc_id, subnet_ids, sg_id = _default_vpc_subnets_and_sg(ctx)
    version = kafka_version or _active_kafka_version(ctx, pick=version_pick)
    broker_node_group_info = {
        "InstanceType": "kafka.m5.large",
        "ClientSubnets": subnet_ids,
        "SecurityGroups": [sg_id],
    }
    if connectivity_info is not None:
        broker_node_group_info["ConnectivityInfo"] = connectivity_info
    provisioned = {
        "BrokerNodeGroupInfo": broker_node_group_info,
        "KafkaVersion": version,
        "NumberOfBrokerNodes": len(subnet_ids),
    }
    if client_authentication is not None:
        provisioned["ClientAuthentication"] = client_authentication
    resp = kafka.create_cluster_v2(ClusterName=ctx.unique_name("sim2real-msk-"), Provisioned=provisioned)
    arn = resp["ClusterArn"]
    ctx.on_cleanup(lambda: _delete_cluster_and_wait(ctx, arn))
    _wait_for_cluster_state(ctx, arn, "ACTIVE")
    return arn


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
