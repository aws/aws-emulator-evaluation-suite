"""compatible-kafka-versions-reflects-active-cluster-state."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "compatible-kafka-versions-reflects-active-cluster-state"
GROUP = "data-plane"
SERVICES = ["kafka"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "cap:c5", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetCompatibleKafkaVersions on an ACTIVE cluster reports its real current version and a
    valid target-version subset of the ListKafkaVersions catalog."""
    kafka = ctx.client("kafka")
    subnet_ids, sg_id = _default_vpc_two_az_subnets(ctx)
    catalog_versions = {v["Version"] for v in kafka.list_kafka_versions().get("KafkaVersions", [])}
    kafka_version = _pick_kafka_version(kafka, catalog_versions)

    name = ctx.unique_name("sim2real-msk-compat-")
    resp = kafka.create_cluster_v2(
        ClusterName=name,
        Provisioned={
            "BrokerNodeGroupInfo": {
                "InstanceType": "kafka.m5.large",
                "ClientSubnets": subnet_ids,
                "SecurityGroups": [sg_id],
            },
            "KafkaVersion": kafka_version,
            "NumberOfBrokerNodes": len(subnet_ids),
        },
        Tags={"sim2real:managed": "true"},
    )
    cluster_arn = resp["ClusterArn"]
    ctx.on_cleanup(lambda: _delete_cluster_and_wait(kafka, cluster_arn))
    _wait_cluster_active(kafka, cluster_arn)

    cluster_info = kafka.describe_cluster_v2(ClusterArn=cluster_arn)["ClusterInfo"]
    actual_current_version = cluster_info["Provisioned"]["CurrentBrokerSoftwareInfo"]["KafkaVersion"]
    assert actual_current_version == kafka_version

    compat = kafka.get_compatible_kafka_versions(ClusterArn=cluster_arn)["CompatibleKafkaVersions"]
    assert compat, "GetCompatibleKafkaVersions returned an empty list for an ACTIVE cluster"
    assert len(compat) == 1, (
        f"a cluster-scoped GetCompatibleKafkaVersions must report exactly one source-version "
        f"entry, got {compat!r}"
    )
    source_versions = {entry["SourceVersion"] for entry in compat}
    assert actual_current_version in source_versions, (
        f"cluster's actual current version {actual_current_version!r} not reported as a "
        f"SourceVersion in {source_versions!r}"
    )
    for entry in compat:
        if entry["SourceVersion"] != actual_current_version:
            continue
        targets = set(entry.get("TargetVersions", []))
        assert targets, "no target upgrade versions reported for the cluster's current version"
        assert actual_current_version not in targets, (
            "the cluster's own current version must not appear as one of its own upgrade targets"
        )
        assert targets <= catalog_versions, (
            f"target versions {targets - catalog_versions} are not in the ListKafkaVersions catalog"
        )


def _default_vpc_two_az_subnets(ctx):
    ec2 = ctx.client("ec2")
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if not vpcs:
        raise AssertionError("account has no shared network VPC to place the MSK cluster in")
    vpc_id = vpcs[0]["VpcId"]
    subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}])["Subnets"]
    by_az = {}
    for s in subnets:
        by_az.setdefault(s["AvailabilityZone"], s["SubnetId"])
    if len(by_az) < 2:
        raise AssertionError("shared network does not span at least 2 Availability Zones")
    subnet_ids = list(by_az.values())[:2]
    sg_id = ec2.describe_security_groups(
        Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "group-name", "Values": ["default"]}]
    )["SecurityGroups"][0]["GroupId"]
    return subnet_ids, sg_id


def _version_key(version: str) -> tuple[tuple[int, ...], str]:
    """Sortable key for a Kafka version string, tolerant of MSK's suffixed variants
    ("2.8.2.tiered", "3.6.0.kraft") -- a plain lexicographic sort orders "3.9.0" ahead of
    "3.10.0", which is wrong."""
    numbers, suffix = [], ""
    for part in version.split("."):
        if part.isdigit():
            numbers.append(int(part))
        else:
            suffix = part
            break
    return (tuple(numbers), suffix)


def _pick_kafka_version(kafka, catalog_versions) -> str:
    resp = kafka.list_kafka_versions()
    active = {v["Version"] for v in resp.get("KafkaVersions", []) if v.get("Status") == "ACTIVE"}
    if not active:
        active = set(catalog_versions)
    if not active:
        raise AssertionError("ListKafkaVersions returned no versions")
    # Pick the highest ACTIVE version that itself has at least one forward upgrade target, so
    # the check never lands on the tip of the catalog with nowhere left to upgrade to.
    compat = kafka.get_compatible_kafka_versions().get("CompatibleKafkaVersions", [])
    upgradable = {e["SourceVersion"] for e in compat if e.get("TargetVersions")} & active
    candidates = upgradable or active
    return max(candidates, key=_version_key)


def _wait_cluster_active(kafka, cluster_arn, timeout_s=1800.0, interval_s=20.0):
    deadline = time.monotonic() + timeout_s
    state = None
    while time.monotonic() < deadline:
        state = kafka.describe_cluster_v2(ClusterArn=cluster_arn)["ClusterInfo"]["State"]
        if state == "ACTIVE":
            return
        if state == "FAILED":
            raise AssertionError(f"cluster {cluster_arn} entered FAILED state")
        time.sleep(interval_s)
    raise AssertionError(f"cluster {cluster_arn} did not reach ACTIVE within {timeout_s}s, last state {state}")


def _delete_cluster_and_wait(kafka, cluster_arn, timeout_s=1800.0, interval_s=20.0):
    try:
        kafka.delete_cluster(ClusterArn=cluster_arn)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NotFoundException":
            raise
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            kafka.describe_cluster_v2(ClusterArn=cluster_arn)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NotFoundException":
                raise
            return
        time.sleep(interval_s)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
