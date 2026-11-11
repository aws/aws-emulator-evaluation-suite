"""cluster-policy-document-round-trip."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "cluster-policy-document-round-trip"
GROUP = "representation"
SERVICES = ["kafka"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A cluster resource policy JSON document written via PutClusterPolicy is
    returned with the identical statements, actions, principals and resources
    by GetClusterPolicy."""
    kafka = ctx.client("kafka")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]
    _, subnets, sg = _default_vpc_and_subnets(ctx)
    version = _pick_kafka_version(ctx, kafka)
    cluster_arn = _create_minimal_cluster(ctx, kafka, subnets, sg, version)
    _wait_for_cluster_active(ctx, kafka, cluster_arn)

    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "AllowCrossAccountDescribe",
                "Effect": "Allow",
                "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"},
                "Action": ["kafka:DescribeClusterV2", "kafka:GetBootstrapBrokers"],
                "Resource": cluster_arn,
            }
        ],
    }
    kafka.put_cluster_policy(ClusterArn=cluster_arn, Policy=json.dumps(policy))
    ctx.on_cleanup(lambda: _delete_policy_ignoring_absence(kafka, cluster_arn))

    fetched = json.loads(kafka.get_cluster_policy(ClusterArn=cluster_arn)["Policy"])
    assert fetched["Version"] == policy["Version"], (
        f"expected Version {policy['Version']!r}, got {fetched.get('Version')!r}"
    )
    assert len(fetched["Statement"]) == 1, (
        f"expected exactly 1 statement, got {len(fetched['Statement'])}: {fetched['Statement']!r}"
    )
    stmt = fetched["Statement"][0]
    assert stmt["Sid"] == "AllowCrossAccountDescribe", f"expected Sid 'AllowCrossAccountDescribe', got {stmt.get('Sid')!r}"
    assert stmt["Effect"] == "Allow", f"expected Effect 'Allow', got {stmt.get('Effect')!r}"
    assert stmt["Resource"] == cluster_arn, f"expected Resource {cluster_arn!r}, got {stmt.get('Resource')!r}"
    assert set(stmt["Action"]) == {"kafka:DescribeClusterV2", "kafka:GetBootstrapBrokers"}, (
        f"expected Action {{'kafka:DescribeClusterV2', 'kafka:GetBootstrapBrokers'}}, got {stmt.get('Action')!r}"
    )
    assert stmt["Principal"]["AWS"] == f"arn:aws:iam::{account_id}:root", (
        f"expected Principal.AWS 'arn:aws:iam::{account_id}:root', got {stmt.get('Principal')!r}"
    )

    kafka.delete_cluster_policy(ClusterArn=cluster_arn)
    code, message = _error_code(lambda: kafka.get_cluster_policy(ClusterArn=cluster_arn))
    assert code == "NotFoundException", f"expected NotFoundException after DeleteClusterPolicy, got {code!r}"
    assert message == "The requested resource doesn\u2019t exist.", message


def _error_code(fn):
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError("expected a ClientError but the call succeeded")


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


def _create_minimal_cluster(ctx, kafka, subnets, sg, version):
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
        Tags={"sim2real:managed": "true"},
    )
    arn = resp["ClusterArn"]
    ctx.on_cleanup(lambda: _delete_cluster(ctx, kafka, arn))
    return arn


def _delete_cluster(ctx, kafka, arn):
    from botocore.exceptions import ClientError

    try:
        kafka.delete_cluster(ClusterArn=arn)
    except ClientError as e:
        if e.response["Error"]["Code"] == "NotFoundException":
            return
        raise


def _delete_policy_ignoring_absence(kafka, cluster_arn):
    from botocore.exceptions import ClientError

    try:
        kafka.delete_cluster_policy(ClusterArn=cluster_arn)
    except ClientError as e:
        if e.response["Error"]["Code"] != "NotFoundException":
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


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
