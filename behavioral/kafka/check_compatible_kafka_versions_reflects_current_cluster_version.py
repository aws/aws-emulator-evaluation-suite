"""compatible-kafka-versions-reflects-current-cluster-version."""
from __future__ import annotations

import re
import time
from typing import Any

from behavioral_harness import tags

CHECK = "compatible-kafka-versions-reflects-current-cluster-version"
GROUP = "server-side"
SERVICES = ["kafka"]

# Standard brokers accept only the 3.8.x / 3.9.x wildcard releases and the KRaft lines today
# ("Valid values: [3.8.x, 3.8.x.kraft, 3.9.x, 3.9.x.kraft, 4.0.x.kraft, 4.1.x.kraft]", observed
# on real AWS), so a release is numeric or ends in .x; KRaft releases are not upgrade targets here.
_NUMERIC_VERSION_RE = re.compile(r"^\d+\.\d+\.(\d+|x)$")
_START_VERSION = "3.8.x"


@tags("axis:happy-path", "cap:c1", "cap:c4", "cap:c5", "concern:representation", "plane:control")
def run(ctx) -> None:
    """After UpdateClusterKafkaVersion completes, the cluster runs the target version and
    GetCompatibleKafkaVersions for it offers neither the original nor the current version as a target."""
    kafka = ctx.client("kafka")

    start_version = _pick_active_kafka_version(ctx)
    cluster_arn = _create_basic_cluster(ctx, start_version)

    before = kafka.get_compatible_kafka_versions(ClusterArn=cluster_arn)["CompatibleKafkaVersions"]
    entry_before = _entry_for(before, start_version)
    assert entry_before is not None, (
        f"GetCompatibleKafkaVersions returned no entry for the cluster's actual "
        f"starting version {start_version!r}: {before!r}"
    )
    targets_before = set(entry_before["TargetVersions"])
    assert start_version not in targets_before, "a version must never list itself as an upgrade target"
    if not targets_before:
        raise AssertionError(
            f"no upgrade targets are available from Kafka version {start_version} in this "
            "account/region, so the forward-upgrade-path assertion cannot be exercised"
        )
    target_version = min(targets_before, key=_version_key)

    cluster_info = kafka.describe_cluster(ClusterArn=cluster_arn)["ClusterInfo"]
    current_version_token = cluster_info["CurrentVersion"]
    op = kafka.update_cluster_kafka_version(
        ClusterArn=cluster_arn,
        CurrentVersion=current_version_token,
        TargetKafkaVersion=target_version,
    )
    _poll_cluster_operation(ctx, op["ClusterOperationArn"])

    updated_info = kafka.describe_cluster(ClusterArn=cluster_arn)["ClusterInfo"]
    actual_version = updated_info["CurrentBrokerSoftwareInfo"]["KafkaVersion"]
    assert actual_version == target_version, (
        f"cluster reports Kafka version {actual_version!r} after the upgrade operation "
        f"completed, expected {target_version!r}"
    )

    after = kafka.get_compatible_kafka_versions(ClusterArn=cluster_arn)["CompatibleKafkaVersions"]
    entry_after = _entry_for(after, target_version)
    assert entry_after is not None, (
        f"GetCompatibleKafkaVersions returned no entry for the cluster's new version "
        f"{target_version!r} after the upgrade: {after!r}"
    )
    targets_after = set(entry_after["TargetVersions"])
    assert start_version not in targets_after, (
        f"the already-surpassed starting version {start_version!r} reappeared as an upgrade "
        f"target after the cluster moved past it: {targets_after!r}"
    )
    assert target_version not in targets_after, "a version must never list itself as an upgrade target"


def _entry_for(compatible_versions: list[dict[str, Any]], source_version: str) -> dict[str, Any] | None:
    for entry in compatible_versions:
        if entry.get("SourceVersion") == source_version:
            return entry
    return None


def _version_key(version: str) -> tuple[int, ...]:
    if not _NUMERIC_VERSION_RE.match(version):
        return (999, 999, 999)
    return tuple(0 if p == "x" else int(p) for p in version.split("."))


def _poll_cluster_operation(ctx, operation_arn: str, timeout_s: float = 5400.0, interval_s: float = 20.0) -> None:
    # A two-broker version upgrade ran past 2700 s on real AWS.
    kafka = ctx.client("kafka")
    deadline = time.monotonic() + timeout_s
    last_state = None
    while time.monotonic() < deadline:
        info = kafka.describe_cluster_operation(ClusterOperationArn=operation_arn)["ClusterOperationInfo"]
        last_state = info["OperationState"]
        if last_state == "UPDATE_COMPLETE":
            return
        if last_state == "UPDATE_FAILED":
            raise AssertionError(f"UpdateClusterKafkaVersion failed: {info.get('ErrorInfo')}")
        time.sleep(interval_s)
    raise AssertionError(f"cluster operation did not complete within {timeout_s}s (last state={last_state})")


def _poll_cluster_state(
    ctx, cluster_arn: str, desired: set[str], timeout_s: float = 3000.0, interval_s: float = 20.0
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
    subnets = ctx.network().subnet_ids[:2]
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
    )
    kwargs.update(extra)
    resp = kafka.create_cluster(**kwargs)
    arn = resp["ClusterArn"]
    ctx.on_cleanup(lambda: _delete_cluster(ctx, arn))
    _poll_cluster_state(ctx, arn, {"ACTIVE"})
    return arn


def _delete_cluster(ctx, arn: str) -> None:
    """DeleteCluster is refused while the cluster is UPDATING, so a running upgrade is let settle
    first (bounded); then the delete is confirmed, and a cluster still present raises."""
    from botocore.exceptions import ClientError

    kafka = ctx.client("kafka")
    try:
        _poll_cluster_state(ctx, arn, {"ACTIVE"}, timeout_s=900.0)
    except AssertionError:
        pass
    try:
        kafka.delete_cluster(ClusterArn=arn)
    except ClientError as e:
        if e.response["Error"]["Code"] == "NotFoundException":
            return
        raise
    deadline = time.monotonic() + 800.0
    while time.monotonic() < deadline:
        try:
            kafka.describe_cluster(ClusterArn=arn)
        except ClientError as e:
            if e.response["Error"]["Code"] == "NotFoundException":
                return
            raise
        time.sleep(20.0)
    raise AssertionError(f"cluster {arn} still present 800s after DeleteCluster")


def _pick_active_kafka_version(ctx) -> str:
    """The lowest Standard-broker release, so an upgrade target exists above it; it is read
    from the first ListKafkaVersions page."""
    kafka = ctx.client("kafka")
    status = {v["Version"]: v.get("Status") for v in kafka.list_kafka_versions().get("KafkaVersions", [])}
    if status.get(_START_VERSION) != "ACTIVE":
        raise AssertionError(f"Kafka {_START_VERSION} is not ACTIVE in ListKafkaVersions: {sorted(status)}")
    return _START_VERSION


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
