"""cluster-policy-invalid-document-rejected."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "cluster-policy-invalid-document-rejected"
GROUP = "representation"
SERVICES = ["kafka"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """PutClusterPolicy rejects a syntactically-invalid policy document (missing
    Effect) with BadRequestException, leaving no policy attached, while a
    well-formed policy on the very same cluster still attaches successfully."""
    kafka = ctx.client("kafka")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]
    _, subnets, sg = _default_vpc_and_subnets(ctx)
    version = _pick_kafka_version(ctx, kafka)
    cluster_arn = _create_minimal_cluster(ctx, kafka, subnets, sg, version)
    _wait_for_cluster_active(ctx, kafka, cluster_arn)
    ctx.on_cleanup(lambda: _delete_policy_ignoring_absence(kafka, cluster_arn))

    invalid_policy = json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    # Missing "Effect" makes this an invalid IAM-style resource policy statement.
                    "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"},
                    "Action": "kafka:DescribeClusterV2",
                    "Resource": cluster_arn,
                }
            ],
        }
    )
    code, message = _error_code(lambda: kafka.put_cluster_policy(ClusterArn=cluster_arn, Policy=invalid_policy))
    assert code == "BadRequestException", f"expected BadRequestException for a policy missing Effect, got {code!r}"
    assert message == "The cluster policy is not valid. Missing required field Effect", (
        f"PutClusterPolicy rejection message: {message!r}"
    )

    # The rejected call must have left no policy attached at all.
    not_found_code, not_found_message = _error_code(lambda: kafka.get_cluster_policy(ClusterArn=cluster_arn))
    assert not_found_code == "NotFoundException", (
        f"expected NotFoundException after the invalid PutClusterPolicy was rejected, got {not_found_code!r}"
    )
    assert not_found_message == "The requested resource doesn\u2019t exist.", (
        f"GetClusterPolicy message: {not_found_message!r}"
    )

    # Positive control: a well-formed policy on the same cluster attaches fine.
    valid_policy = json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "AllowDescribe",
                    "Effect": "Allow",
                    "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"},
                    "Action": "kafka:DescribeClusterV2",
                    "Resource": cluster_arn,
                }
            ],
        }
    )
    kafka.put_cluster_policy(ClusterArn=cluster_arn, Policy=valid_policy)
    fetched = json.loads(kafka.get_cluster_policy(ClusterArn=cluster_arn)["Policy"])
    assert fetched["Statement"][0]["Sid"] == "AllowDescribe", (
        f"expected the well-formed policy to attach and read back with Sid=AllowDescribe, got {fetched!r}"
    )


def _error_code(fn):
    """Call fn(); return its botocore error (code, message). An unexpected SUCCESS raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


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
        _wait_until_deletable(kafka, arn)
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
