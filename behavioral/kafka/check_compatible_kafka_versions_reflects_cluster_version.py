"""compatible-kafka-versions-reflects-cluster-version."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "compatible-kafka-versions-reflects-cluster-version"
GROUP = "data-plane"
SERVICES = ["kafka"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "cap:c5", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetCompatibleKafkaVersions for an existing cluster reports that cluster's
    own current version as the source and a bounded, non-empty set of upgrade
    targets -- not the full version catalog returned when no ClusterArn is given."""
    kafka = ctx.client("kafka")
    subnets, sg = _provision_network(ctx)
    all_versions = kafka.list_kafka_versions()["KafkaVersions"]
    version = _pick_older_active_version(all_versions)

    name = ctx.unique_name("sim2real-behav-kafka-")
    resp = kafka.create_cluster_v2(
        ClusterName=name,
        Provisioned={
            "BrokerNodeGroupInfo": {
                "InstanceType": "kafka.t3.small",
                "ClientSubnets": subnets,
                "SecurityGroups": [sg],
                "StorageInfo": {"EbsStorageInfo": {"VolumeSize": 10}},
            },
            "KafkaVersion": version,
            "NumberOfBrokerNodes": len(subnets),
        },
    )
    cluster_arn = resp["ClusterArn"]
    ctx.on_cleanup(lambda: _delete_cluster(ctx, kafka, cluster_arn))
    info = _wait_for_cluster_active(ctx, kafka, cluster_arn)
    active_version = info["Provisioned"]["CurrentBrokerSoftwareInfo"]["KafkaVersion"]
    assert active_version == version, f"expected cluster to report its provisioned version {version!r}, got {active_version!r}"

    catalog_versions = {v["Version"] for v in all_versions}
    scoped = kafka.get_compatible_kafka_versions(ClusterArn=cluster_arn)["CompatibleKafkaVersions"]
    assert len(scoped) == 1, "a cluster-scoped query must report exactly one source-version entry"
    entry = scoped[0]
    assert entry["SourceVersion"] == version, f"expected SourceVersion {version!r}, got {entry['SourceVersion']!r}"
    targets = set(entry["TargetVersions"])
    assert targets, "cluster on an old version must have at least one upgrade target"
    assert version not in targets, "the cluster's own version must not appear as an upgrade target"
    # The cluster-scoped response must be a strict subset of the full catalog, not the catalog itself.
    assert targets < catalog_versions, (
        f"expected cluster-scoped targets {targets!r} to be a strict subset of the full catalog {catalog_versions!r}"
    )




def _provision_network(ctx, count=2):
    """A private VPC, subnets and security group for MSK broker ENIs, owned by the check because
    an account may have no default VPC."""
    ec2 = ctx.client("ec2")

    def _tags(resource_type):
        return [{"ResourceType": resource_type, "Tags": [{"Key": "Name", "Value": ctx.unique_name("sim2real-msk-net-")}]}]

    vpc_id = ec2.create_vpc(CidrBlock="10.98.0.0/16", TagSpecifications=_tags("vpc"))["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: _delete_net(ec2, "delete_vpc", VpcId=vpc_id))

    azs = [a["ZoneName"] for a in ec2.describe_availability_zones()["AvailabilityZones"][:count]]
    if len(azs) < count:
        raise AssertionError(f"region does not have {count} availability zones available to place MSK broker ENIs")
    subnet_ids = []
    for i, az in enumerate(azs):
        subnet_id = ec2.create_subnet(
            VpcId=vpc_id, CidrBlock=f"10.98.{i}.0/24", AvailabilityZone=az, TagSpecifications=_tags("subnet")
        )["Subnet"]["SubnetId"]
        ctx.on_cleanup(lambda sid=subnet_id: _delete_net(ec2, "delete_subnet", SubnetId=sid))
        subnet_ids.append(subnet_id)

    sg_id = ec2.create_security_group(
        VpcId=vpc_id,
        GroupName=ctx.unique_name("sim2real-msk-sg-"),
        Description="sim2real compatible-kafka-versions cluster-version test",
        TagSpecifications=_tags("security-group"),
    )["GroupId"]
    ctx.on_cleanup(lambda: _delete_net(ec2, "delete_security_group", GroupId=sg_id))

    return subnet_ids, sg_id


def _version_key(version):
    """Numeric sort key for a Kafka version, tolerant of suffixes ("2.8.2.tiered", "3.6.0.kraft").

    Lexicographic order would put "2.10.1" before "2.9.1"."""
    numbers, suffix = [], ""
    for part in version.split("."):
        if part.isdigit():
            numbers.append(int(part))
        else:
            suffix = part
            break
    return (tuple(numbers), suffix)


def _pick_older_active_version(all_versions):

    # Standard brokers accept only 3.8.x and later; 4.x is KRaft-only and has no ZooKeeper upgrade.
    active = [
        v["Version"]
        for v in all_versions
        if v.get("Status") == "ACTIVE" and v["Version"].split(".")[:2] in (["3", "8"], ["3", "9"])
        and "kraft" not in v["Version"]
    ]
    if len(active) < 2:
        raise AssertionError("account's Kafka version catalog has fewer than 2 ACTIVE versions to test an upgrade path")
    # Pick the numerically oldest ACTIVE version so it is guaranteed to have at least one
    # compatible upgrade target.
    return min(active, key=_version_key)


def _delete_cluster(ctx, kafka, arn):
    from botocore.exceptions import ClientError

    try:
        kafka.delete_cluster(ClusterArn=arn)
    except ClientError as e:
        if e.response["Error"]["Code"] == "NotFoundException":
            return
        raise


def _wait_for_cluster_active(ctx, kafka, arn, timeout_s=1800, interval_s=20):
    deadline = time.monotonic() + timeout_s
    last_state = None
    while time.monotonic() < deadline:
        info = kafka.describe_cluster_v2(ClusterArn=arn)["ClusterInfo"]
        last_state = info["State"]
        if last_state == "ACTIVE":
            return info
        if last_state == "FAILED":
            raise AssertionError(f"cluster {arn} entered FAILED state")
        time.sleep(interval_s)
    raise AssertionError(f"cluster {arn} did not reach ACTIVE within {timeout_s}s (last={last_state})")


# AWS-managed ENIs (clusters, endpoints, functions, ...) leave a VPC asynchronously after their
# owner's delete returns, so an immediate DeleteSubnet / DeleteSecurityGroup / DeleteVpc fails with
# DependencyViolation. Wait (bounded) for the ENIs to go, retry DependencyViolation inside the same
# window, and raise a final failure naming the ENIs still attached. The window is shared by all of
# one check's network deletes and fits the 900s cleanup budget.
_NET_TEARDOWN_S = 630.0
_NET_ENI_FILTER = {"VpcId": "vpc-id", "SubnetId": "subnet-id", "GroupId": "group-id"}
_NET_DEADLINES: dict = {}


def _delete_net(client, op, **ident):
    import time as _time

    from botocore.exceptions import ClientError as _ClientError

    held = _NET_DEADLINES.get(id(client))
    if held is None or held[0] is not client:
        held = _NET_DEADLINES[id(client)] = (client, _time.monotonic() + _NET_TEARDOWN_S)
    deadline = held[1]
    flt = [{"Name": _NET_ENI_FILTER[k], "Values": [v]} for k, v in ident.items() if k in _NET_ENI_FILTER]
    while _net_enis(client, flt) and _time.monotonic() < deadline:
        _time.sleep(10)
    while True:
        try:
            return getattr(client, op)(**ident)
        except _ClientError as exc:
            code = exc.response.get("Error", {}).get("Code", "")
            if code != "DependencyViolation":
                raise
            if _time.monotonic() >= deadline:
                # Same exception type and code, so a caller catching ClientError still collects it.
                raise type(exc)(
                    {**exc.response, "Error": {**exc.response.get("Error", {}), "Message": (
                        f"{op}({ident}): DependencyViolation after {_NET_TEARDOWN_S}s; "
                        f"ENIs still attached: {_net_enis(client, flt)}"
                    )}},
                    exc.operation_name,
                ) from exc
        _time.sleep(10)


def _net_enis(client, flt):
    from botocore.exceptions import ClientError as _ClientError

    if not flt:
        return []
    try:
        enis = client.describe_network_interfaces(Filters=flt)["NetworkInterfaces"]
    except _ClientError:
        return []  # a diagnostic only: the delete itself still reports its own failure
    return [f"{e['NetworkInterfaceId']}:{e.get('InterfaceType') or e.get('Description', '')[:40]}" for e in enis]


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
