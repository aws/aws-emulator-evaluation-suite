"""bootstrap-brokers-endpoint-formats-match-cluster-security."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "bootstrap-brokers-endpoint-formats-match-cluster-security"
GROUP = "data-plane"
SERVICES = ["kafka"]

_CLUSTER_WAIT_TIMEOUT_S = 1800
_CLUSTER_POLL_INTERVAL_S = 30


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetBootstrapBrokers only returns the endpoint families that match the cluster's actually
    configured client authentication (SASL/IAM only here, no TLS/SCRAM/public/multi-VPC)."""
    cluster_arn = _create_provisioned_cluster(
        ctx,
        client_authentication={"Sasl": {"Iam": {"Enabled": True}}},
    )
    kafka = ctx.client("kafka")

    cluster_info = kafka.describe_cluster(ClusterArn=cluster_arn)["ClusterInfo"]
    client_auth = cluster_info["ClientAuthentication"]
    assert client_auth.get("Sasl", {}).get("Iam", {}).get("Enabled") is True, (
        f"expected Sasl.Iam.Enabled True on the cluster we just created, got {client_auth.get('Sasl')!r}"
    )
    assert not client_auth.get("Sasl", {}).get("Scram", {}).get("Enabled"), (
        f"SASL/SCRAM was never configured but ClientAuthentication reports it enabled: {client_auth.get('Sasl')!r}"
    )
    assert not client_auth.get("Tls", {}).get("Enabled"), (
        f"TLS mutual auth was never configured but ClientAuthentication reports it enabled: {client_auth.get('Tls')!r}"
    )
    assert not client_auth.get("Unauthenticated", {}).get("Enabled"), (
        "Unauthenticated access was never configured but ClientAuthentication reports it enabled: "
        f"{client_auth.get('Unauthenticated')!r}"
    )

    brokers = kafka.get_bootstrap_brokers(ClusterArn=cluster_arn)

    assert brokers.get("BootstrapBrokerStringSaslIam"), "expected a populated SASL/IAM bootstrap broker string"
    for absent_field in (
        "BootstrapBrokerString",
        "BootstrapBrokerStringTls",
        "BootstrapBrokerStringSaslScram",
        "BootstrapBrokerStringPublicTls",
        "BootstrapBrokerStringPublicSaslScram",
        "BootstrapBrokerStringPublicSaslIam",
        "BootstrapBrokerStringVpcConnectivityTls",
        "BootstrapBrokerStringVpcConnectivitySaslScram",
        "BootstrapBrokerStringVpcConnectivitySaslIam",
    ):
        assert not brokers.get(absent_field), (
            f"{absent_field} should be absent for a SASL/IAM-only, non-public, non-multi-VPC cluster "
            f"but was {brokers.get(absent_field)!r}"
        )


# ===== helpers =====
def _default_vpc_subnets_and_sg(ctx):
    ec2 = ctx.client("ec2")
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if not vpcs:
        raise AssertionError("no shared network VPC available in this account/region to provision an MSK broker cluster")
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


# version_pick defaults to "oldest": the newest ACTIVE version can require a broker
# instance family this check does not use (kafka.m5.large is a Standard type, and MSK
# has started shipping kraft-only versions Standard does not support), which is not
# what this check is testing. Any ACTIVE version satisfies the auth/endpoint contract.
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


def _wait_for_cluster_state(
    ctx, arn, target_state, timeout_s=_CLUSTER_WAIT_TIMEOUT_S, interval_s=_CLUSTER_POLL_INTERVAL_S
):
    kafka = ctx.client("kafka")
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        info = kafka.describe_cluster(ClusterArn=arn)["ClusterInfo"]
        last = info["State"]
        if last == target_state:
            return info
        if last == "FAILED":
            raise AssertionError(f"cluster {arn} entered FAILED state while waiting for {target_state}")
        time.sleep(interval_s)
    raise AssertionError(f"cluster {arn} did not reach {target_state} within {timeout_s}s (last observed: {last})")


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
    ctx, *, client_authentication=None, connectivity_info=None, kafka_version=None, version_pick="oldest"
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
    resp = kafka.create_cluster_v2(
        ClusterName=ctx.unique_name("sim2real-msk-"),
        Provisioned=provisioned,
        Tags={"sim2real:managed": "true"},
    )
    arn = resp["ClusterArn"]
    ctx.on_cleanup(lambda: _delete_cluster_and_wait(ctx, arn))
    _wait_for_cluster_state(ctx, arn, "ACTIVE")
    return arn


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
