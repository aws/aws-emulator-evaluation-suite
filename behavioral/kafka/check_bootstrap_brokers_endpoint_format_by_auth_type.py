"""bootstrap-brokers-endpoint-format-by-auth-type."""
from __future__ import annotations

import re
import time

from behavioral_harness import tags

CHECK = "bootstrap-brokers-endpoint-format-by-auth-type"
GROUP = "data-plane"
SERVICES = ["kafka"]

_HOST_PORT_RE = re.compile(r"^[A-Za-z0-9.\-]+:\d+(,[A-Za-z0-9.\-]+:\d+)*$")


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetBootstrapBrokers fails with BadRequestException while the cluster is CREATING, then returns
    distinct host:port SASL/SCRAM and SASL/IAM strings and no plaintext, TLS or public TLS string for a
    SCRAM + IAM cluster."""
    kafka = ctx.client("kafka")
    _, subnets, sg = _default_vpc_and_subnets(ctx)
    version = _pick_kafka_version(ctx, kafka)
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
            "EncryptionInfo": {"EncryptionInTransit": {"ClientBroker": "TLS"}},
            "ClientAuthentication": {"Sasl": {"Scram": {"Enabled": True}, "Iam": {"Enabled": True}}},
        },
        Tags={"sim2real:managed": "true"},
    )
    cluster_arn = resp["ClusterArn"]
    ctx.on_cleanup(lambda: _delete_cluster(ctx, kafka, cluster_arn))

    # Negative, distinct boundary (state-conflict): the cluster is CREATING right
    # after CreateClusterV2 returns, so bootstrap brokers cannot be resolved yet.
    code, message = _error_code(lambda: kafka.get_bootstrap_brokers(ClusterArn=cluster_arn))
    assert code == "BadRequestException", f"expected BadRequestException while CREATING, got {code!r}"
    assert message == "You can't get bootstrap broker nodes for a cluster in CREATING state.", message

    info = _wait_for_cluster_active(ctx, kafka, cluster_arn)
    client_auth = info["Provisioned"]["ClientAuthentication"]
    assert client_auth["Sasl"]["Scram"]["Enabled"] is True, f"SCRAM not enabled on ACTIVE cluster: {client_auth}"
    assert client_auth["Sasl"]["Iam"]["Enabled"] is True, f"IAM not enabled on ACTIVE cluster: {client_auth}"

    # Positive control: once ACTIVE, the same call now succeeds and returns
    # exactly the endpoint families that match the enabled auth methods.
    brokers = kafka.get_bootstrap_brokers(ClusterArn=cluster_arn)
    scram = brokers.get("BootstrapBrokerStringSaslScram")
    iam = brokers.get("BootstrapBrokerStringSaslIam")
    assert scram and _HOST_PORT_RE.match(scram), f"malformed SASL/SCRAM broker string: {scram!r}"
    assert iam and _HOST_PORT_RE.match(iam), f"malformed SASL/IAM broker string: {iam!r}"
    assert scram != iam, "SCRAM and IAM broker strings must use distinct ports"
    assert not brokers.get("BootstrapBrokerString"), "plaintext endpoint must not be offered"
    assert not brokers.get("BootstrapBrokerStringTls"), "unauthenticated TLS endpoint must not be offered"
    assert not brokers.get("BootstrapBrokerStringPublicTls"), "no public access was configured"


def _error_code(fn):
    """Call fn(); return (Error.Code, Error.Message) of the ClientError it raises. An unexpected
    SUCCESS raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be refused, but it SUCCEEDED and returned {result!r}")


def _default_vpc_and_subnets(ctx, count=2):

    ec2 = ctx.client("ec2")
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if not vpcs:
        raise AssertionError("no shared network VPC available to place MSK broker ENIs")
    vpc_id = vpcs[0]["VpcId"]
    subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}])["Subnets"]
    by_az = {}
    for s in subnets:
        by_az.setdefault(s["AvailabilityZone"], s["SubnetId"])
    if len(by_az) < count:
        raise AssertionError("shared network does not span enough AZs for an MSK cluster")
    sg = ec2.describe_security_groups(
        Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "group-name", "Values": ["default"]}]
    )["SecurityGroups"][0]["GroupId"]
    return vpc_id, list(by_az.values())[:count], sg


def _pick_kafka_version(ctx, kafka):
    versions = kafka.list_kafka_versions()["KafkaVersions"]
    active = [v["Version"] for v in versions if v.get("Status") == "ACTIVE"]
    if "3.9.x" in active:  # recommended, still ZooKeeper; older Standard versions are refused
        return "3.9.x"
    return (active or [v["Version"] for v in versions])[0]


def _delete_cluster(ctx, kafka, arn):
    from botocore.exceptions import ClientError

    try:
        _wait_until_deletable(kafka, arn)
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


def _wait_until_deletable(kafka, arn, timeout_s=1500.0, interval_s=20.0):
    """MSK refuses DeleteCluster while the cluster is still CREATING or UPDATING; wait it out."""
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            state = kafka.describe_cluster_v2(ClusterArn=arn)["ClusterInfo"]["State"]
        except ClientError as e:
            if e.response["Error"]["Code"] == "NotFoundException":
                return
            raise
        if state not in ("CREATING", "UPDATING", "REBOOTING_BROKER", "HEALING"):
            return
        time.sleep(interval_s)

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
