"""cluster-policy-json-round-trip."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cluster-policy-json-round-trip"
GROUP = "representation"
SERVICES = ["kafka"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A complex resource policy (nested JSON, unicode) round-trips byte-for-byte through Get/PutClusterPolicy."""
    kafka = ctx.client("kafka")
    cluster_arn = _create_and_wait_cluster(ctx, kafka)

    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "AllowCrossAccount",
                "Effect": "Allow",
                "Principal": {"AWS": f"arn:aws:iam::{ctx.account}:root"},
                "Action": ["kafka-cluster:Connect", "kafka-cluster:DescribeCluster"],
                "Resource": cluster_arn,
                "Condition": {
                    "StringEquals": {"aws:PrincipalTag/team": "d\u00e9veloppement"},
                    "Bool": {"aws:SecureTransport": "true"},
                },
            }
        ],
    }
    policy_json = json.dumps(policy, ensure_ascii=False)

    kafka.put_cluster_policy(ClusterArn=cluster_arn, Policy=policy_json)
    ctx.on_cleanup(lambda: kafka.delete_cluster_policy(ClusterArn=cluster_arn))

    fetched = kafka.get_cluster_policy(ClusterArn=cluster_arn)
    round_tripped = json.loads(fetched["Policy"])
    assert round_tripped == policy, (
        f"policy document was not returned byte-identical after parsing: sent {policy!r}, "
        f"got {round_tripped!r}"
    )


def _default_vpc_two_az_subnets(ctx):
    ec2 = ctx.client("ec2")
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if not vpcs:
        raise AssertionError("account has no shared network to place the MSK cluster in")
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


def _kafka_versions_desc(kafka) -> list[str]:
    resp = kafka.list_kafka_versions()
    versions = [v["Version"] for v in resp.get("KafkaVersions", []) if v.get("Status") == "ACTIVE"]
    if not versions:
        versions = [v["Version"] for v in resp.get("KafkaVersions", [])]
    if not versions:
        raise AssertionError("ListKafkaVersions returned no versions")
    return sorted(versions, reverse=True)


def _create_and_wait_cluster(ctx, kafka, timeout_s=1800.0, interval_s=20.0):
    subnet_ids, sg_id = _default_vpc_two_az_subnets(ctx)
    name = ctx.unique_name("sim2real-msk-")
    provisioned_base = {
        "BrokerNodeGroupInfo": {
            "InstanceType": "kafka.m5.large",
            "ClientSubnets": subnet_ids,
            "SecurityGroups": [sg_id],
        },
        "NumberOfBrokerNodes": len(subnet_ids),
    }

    # ListKafkaVersions's ACTIVE set can include newer Kraft releases that are
    # Express-only and reject a standard broker instance type at CreateClusterV2
    # time (observed: BadRequestException "Standard instance types are not
    # supported for Kafka version 4.2.x.kraft"). Rather than hardcode which
    # versions are standard-eligible, walk newest-to-oldest and let the
    # service's own rejection of that one specific, narrow error tell us to
    # try the next; any other error is a real failure.
    cluster_arn = None
    last_error: ClientError | None = None
    for kafka_version in _kafka_versions_desc(kafka):
        try:
            resp = kafka.create_cluster_v2(
                ClusterName=name,
                Provisioned={**provisioned_base, "KafkaVersion": kafka_version},
                Tags={"sim2real:managed": "true"},
            )
        except ClientError as e:
            err = e.response.get("Error", {})
            if err.get("Code") == "BadRequestException" and "Standard instance types are not supported" in err.get(
                "Message", ""
            ):
                last_error = e
                continue
            raise
        cluster_arn = resp["ClusterArn"]
        break
    if cluster_arn is None:
        raise AssertionError(
            f"no ACTIVE Kafka version accepted a standard-instance-type MSK cluster: {last_error}"
        )
    ctx.on_cleanup(lambda: _delete_cluster_and_wait(kafka, cluster_arn))

    deadline = time.monotonic() + timeout_s
    state = None
    while time.monotonic() < deadline:
        state = kafka.describe_cluster_v2(ClusterArn=cluster_arn)["ClusterInfo"]["State"]
        if state == "ACTIVE":
            return cluster_arn
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
