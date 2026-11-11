"""bootstrap-brokers-endpoint-types-match-security-config."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "bootstrap-brokers-endpoint-types-match-security-config"
GROUP = "data-plane"
SERVICES = ["kafka"]

# The highest ACTIVE version isn't safe to pick blindly: real AWS rejects some of the
# newest (kraft-only) versions for a Standard (non-Express) broker instance type such
# as kafka.m5.large, and MSK no longer accepts the older 3.x versions with standard
# broker types. 3.9.x is the newest version that still takes a Standard broker.
_DEFAULT_KAFKA_VERSION = "3.9.x"

# Every BootstrapBrokerString* field on the GetBootstrapBrokers response.
_ALL_ENDPOINT_FIELDS = [
    "BootstrapBrokerString",
    "BootstrapBrokerStringTls",
    "BootstrapBrokerStringSaslScram",
    "BootstrapBrokerStringSaslIam",
    "BootstrapBrokerStringPublicTls",
    "BootstrapBrokerStringPublicSaslScram",
    "BootstrapBrokerStringPublicSaslIam",
    "BootstrapBrokerStringVpcConnectivityTls",
    "BootstrapBrokerStringVpcConnectivitySaslScram",
    "BootstrapBrokerStringVpcConnectivitySaslIam",
]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetBootstrapBrokers on a SASL/SCRAM-only, TLS-in-transit cluster exposes the SASL/SCRAM
    endpoint and none of plaintext, mTLS, SASL/IAM, or any public/VPC-connectivity variant."""
    kafka = ctx.client("kafka")
    subnet_ids, sg_id = _default_vpc_two_az_subnets(ctx)
    name = ctx.unique_name("sim2real-msk-scram-")
    resp = kafka.create_cluster_v2(
        ClusterName=name,
        Provisioned={
            "BrokerNodeGroupInfo": {
                "InstanceType": "kafka.m5.large",
                "ClientSubnets": subnet_ids,
                "SecurityGroups": [sg_id],
            },
            "KafkaVersion": _DEFAULT_KAFKA_VERSION,
            "NumberOfBrokerNodes": len(subnet_ids),
            "ClientAuthentication": {
                "Sasl": {"Scram": {"Enabled": True}},
                "Tls": {"Enabled": False},
                "Unauthenticated": {"Enabled": False},
            },
            "EncryptionInfo": {"EncryptionInTransit": {"ClientBroker": "TLS"}},
        },
        Tags={"sim2real:managed": "true"},
    )
    cluster_arn = resp["ClusterArn"]
    ctx.on_cleanup(lambda: _delete_cluster_and_wait(kafka, cluster_arn))
    _wait_cluster_active(kafka, cluster_arn)

    cluster_info = kafka.describe_cluster_v2(ClusterArn=cluster_arn)["ClusterInfo"]
    client_auth = cluster_info["Provisioned"]["ClientAuthentication"]
    assert client_auth["Sasl"]["Scram"]["Enabled"] is True
    assert not client_auth.get("Tls", {}).get("Enabled")
    assert not client_auth.get("Unauthenticated", {}).get("Enabled")

    brokers = kafka.get_bootstrap_brokers(ClusterArn=cluster_arn)
    present = {f for f in _ALL_ENDPOINT_FIELDS if brokers.get(f)}
    assert present == {"BootstrapBrokerStringSaslScram"}, (
        f"expected exactly {{'BootstrapBrokerStringSaslScram'}} populated, got {present!r} "
        f"(full response keys with values: {present})"
    )
    assert "," in brokers["BootstrapBrokerStringSaslScram"] or ":" in brokers["BootstrapBrokerStringSaslScram"]


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
