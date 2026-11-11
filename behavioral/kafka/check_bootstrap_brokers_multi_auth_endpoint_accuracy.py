"""bootstrap-brokers-multi-auth-endpoint-accuracy."""
from __future__ import annotations

import time
from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "bootstrap-brokers-multi-auth-endpoint-accuracy"
GROUP = "server-side"
SERVICES = ["kafka"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetBootstrapBrokers for a cluster with unauthenticated, SCRAM and IAM auth over TLS_PLAINTEXT
    returns four distinct strings, each mechanism on its own single port, and no public or
    VPC-connectivity strings."""
    kafka_version = _pick_active_kafka_version(ctx)
    cluster_arn = _create_v2_cluster(
        ctx,
        kafka_version,
        client_authentication={
            "Unauthenticated": {"Enabled": True},
            "Sasl": {"Scram": {"Enabled": True}, "Iam": {"Enabled": True}},
        },
        encryption_info={"EncryptionInTransit": {"ClientBroker": "TLS_PLAINTEXT", "InCluster": True}},
    )
    kafka = ctx.client("kafka")

    brokers = kafka.get_bootstrap_brokers(ClusterArn=cluster_arn)

    plaintext = brokers.get("BootstrapBrokerString")
    tls = brokers.get("BootstrapBrokerStringTls")
    scram = brokers.get("BootstrapBrokerStringSaslScram")
    iam = brokers.get("BootstrapBrokerStringSaslIam")

    assert plaintext, "expected a plaintext bootstrap broker string (unauthenticated enabled)"
    assert tls, "expected a TLS bootstrap broker string (ClientBroker allows TLS)"
    assert scram, "expected a SASL/SCRAM bootstrap broker string (Sasl.Scram enabled)"
    assert iam, "expected a SASL/IAM bootstrap broker string (Sasl.Iam enabled)"

    assert len(_ports(plaintext)) == 1, f"plaintext endpoint used more than one port: {plaintext!r}"
    assert len(_ports(tls)) == 1, f"TLS endpoint used more than one port: {tls!r}"
    assert len(_ports(scram)) == 1, f"SASL/SCRAM endpoint used more than one port: {scram!r}"
    assert len(_ports(iam)) == 1 and len(_ports(plaintext) | _ports(tls) | _ports(scram) | _ports(iam)) == 4, (
        f"SASL/IAM endpoint used more than one port, or the four mechanisms do not each have their own "
        f"port: {plaintext!r} {tls!r} {scram!r} {iam!r}")

    # The four mechanism endpoints must be genuinely distinct connection strings.
    distinct = {plaintext, tls, scram, iam}
    assert len(distinct) == 4, f"expected 4 distinct bootstrap endpoints, got {len(distinct)}: {distinct!r}"

    # No public access or client-VPC connectivity was configured, so those
    # endpoint families must be absent entirely, not empty placeholders.
    for absent_field in (
        "BootstrapBrokerStringPublicTls",
        "BootstrapBrokerStringPublicSaslScram",
        "BootstrapBrokerStringPublicSaslIam",
        "BootstrapBrokerStringVpcConnectivityTls",
        "BootstrapBrokerStringVpcConnectivitySaslScram",
        "BootstrapBrokerStringVpcConnectivitySaslIam",
    ):
        assert absent_field not in brokers, f"{absent_field} should be absent, got {brokers.get(absent_field)!r}"


def _ports(bootstrap_string: str) -> set[str]:
    return {entry.rsplit(":", 1)[1] for entry in bootstrap_string.split(",") if entry}


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


def _poll_cluster_state_v2(
    ctx, cluster_arn: str, desired: set[str], timeout_s: float = 1800.0, interval_s: float = 20.0
) -> dict[str, Any]:
    kafka = ctx.client("kafka")
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        info = kafka.describe_cluster_v2(ClusterArn=cluster_arn)["ClusterInfo"]
        last = info["State"]
        if last in desired:
            return info
        if last == "FAILED":
            raise AssertionError(f"cluster entered FAILED state: {info.get('StateInfo')}")
        time.sleep(interval_s)
    raise AssertionError(f"cluster did not reach {desired} within {timeout_s}s (last state={last})")


def _create_v2_cluster(
    ctx,
    kafka_version: str,
    client_authentication: dict[str, Any],
    encryption_info: dict[str, Any],
) -> str:
    kafka = ctx.client("kafka")
    subnets = _default_client_subnets(ctx, 2)
    name = ctx.unique_name("sim2real-behav-")
    resp = kafka.create_cluster_v2(
        ClusterName=name,
        Provisioned={
            "KafkaVersion": kafka_version,
            "NumberOfBrokerNodes": len(subnets),
            "BrokerNodeGroupInfo": {
                "InstanceType": "kafka.t3.small",
                "ClientSubnets": subnets,
                "StorageInfo": {"EbsStorageInfo": {"VolumeSize": 100}},
            },
            "ClientAuthentication": client_authentication,
            "EncryptionInfo": encryption_info,
        },
    )
    arn = resp["ClusterArn"]
    ctx.on_cleanup(lambda: _delete_cluster_when_settled(kafka, arn))
    _poll_cluster_state_v2(ctx, arn, {"ACTIVE"})
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
