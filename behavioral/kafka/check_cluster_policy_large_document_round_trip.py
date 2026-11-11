"""cluster-policy-large-document-round-trip."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "cluster-policy-large-document-round-trip"
GROUP = "data-plane"
SERVICES = ["kafka"]

_CLUSTER_WAIT_TIMEOUT_S = 1800
_CLUSTER_POLL_INTERVAL_S = 30


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A large multi-statement policy put with non-canonical indentation comes back from GetClusterPolicy
    as canonical compact JSON, every statement, condition and value intact and in order (MSK does not
    echo the request bytes verbatim)."""
    # "latest" ACTIVE version currently resolves to a kraft-mode release AWS rejects for a
    # Standard broker instance type ("Standard instance types are not supported for Kafka
    # version 4.2.x.kraft", observed on real AWS) -- the policy contract under test here has
    # nothing to do with which Kafka version is newest, so pin to the oldest ACTIVE version,
    # which AWS's own error confirmed is Standard-instance-compatible.
    cluster_arn = _create_provisioned_cluster(ctx, version_pick="oldest")
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    kafka = ctx.client("kafka")

    policy = {
        "Version": "2012-10-17",
        "Id": "sim2real-large-cluster-policy",
        "Statement": [
            {
                "Sid": "AllowRootDescribeCluster",
                "Effect": "Allow",
                "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"},
                "Action": "kafka:DescribeCluster",
                "Resource": cluster_arn,
            },
            {
                "Sid": "AllowRootGetBootstrapBrokers",
                "Effect": "Allow",
                "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"},
                "Action": "kafka:GetBootstrapBrokers",
                "Resource": cluster_arn,
            },
            {
                # kafka:ListNodes and kafka:ListTagsForResource are not valid cluster-policy
                # actions -- confirmed on real AWS: PutClusterPolicy rejected both by name with
                # BadRequestException. kafka:DescribeClusterV2 and kafka:CreateVpcConnection are
                # the documented cluster-policy actions
                # (docs.aws.amazon.com/msk/latest/developerguide/mvpc-cluster-owner-action-policy.html).
                "Sid": "AllowRootDescribeClusterV2AndCreateVpcConnection",
                "Effect": "Allow",
                "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"},
                "Action": ["kafka:DescribeClusterV2", "kafka:CreateVpcConnection"],
                "Resource": cluster_arn,
            },
            {
                # kafka:DeleteCluster is also not a valid cluster-policy action -- confirmed on
                # real AWS: PutClusterPolicy rejected it by name with BadRequestException too, on
                # top of the ListNodes/ListTagsForResource rejection above. Only the four
                # documented cluster-policy actions (DescribeCluster, DescribeClusterV2,
                # GetBootstrapBrokers, CreateVpcConnection) are accepted, so the deny leg reuses
                # DescribeCluster -- same action as the first Allow statement, opposite effect,
                # gated on the same condition -- to keep a real Allow/Deny-with-condition pair.
                "Sid": "DenyRootDescribeClusterOverInsecureTransport",
                "Effect": "Deny",
                "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"},
                "Action": "kafka:DescribeCluster",
                "Resource": cluster_arn,
                "Condition": {"Bool": {"aws:SecureTransport": "false"}},
            },
        ],
    }
    # Deliberately non-canonical indentation/spacing on submission: a real emulator bug is to
    # mis-handle a larger payload by truncating it or dropping/reordering statements when it
    # re-serializes. Real AWS re-serializes to canonical compact JSON rather than echoing the
    # submitted bytes, so that -- not byte-identity with what we sent -- is the contract here.
    policy_text = json.dumps(policy, indent=3, separators=(",", ": "))
    expected = json.dumps(policy, separators=(",", ":"))

    kafka.put_cluster_policy(ClusterArn=cluster_arn, Policy=policy_text)
    fetched = kafka.get_cluster_policy(ClusterArn=cluster_arn)

    assert fetched["Policy"] == expected, (
        f"GetClusterPolicy did not canonicalize the large policy document to compact JSON with "
        f"every statement intact and in order: expected {expected!r}, got {fetched['Policy']!r}"
    )
    # Belt-and-suspenders: also confirm statement order/content parses back identically.
    parsed = json.loads(fetched["Policy"])
    assert parsed == policy, f"parsed policy diverged from what was sent: expected {policy!r}, got {parsed!r}"


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
