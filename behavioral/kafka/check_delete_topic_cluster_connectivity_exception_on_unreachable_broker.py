"""delete-topic-cluster-connectivity-exception-on-unreachable-broker."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "delete-topic-cluster-connectivity-exception-on-unreachable-broker"
GROUP = "error-semantics"
SERVICES = ["kafka"]

# The suite's cleanup budget, shared by the cluster delete and the security group delete after it.
_CLEANUP_BUDGET_S = 1800.0


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """With every ingress rule revoked from the cluster's security group, DeleteTopic still succeeds
    and the topic is removed: a security group gates traffic to broker ENIs, not MSK's admin path."""
    cluster_arn, _subnets, sg_id = _create_provisioned_cluster(ctx, num_brokers=2)
    canary_topic = _create_topic(ctx, cluster_arn)
    topic_name = _create_topic(ctx, cluster_arn)

    ec2 = ctx.client("ec2")
    kafka = ctx.client("kafka")

    # Positive control: with connectivity intact, DeleteTopic works normally. Without this,
    # a target that rejects every DeleteTopic would pass just as well as one that only rejects
    # it while the brokers are unreachable.
    kafka.delete_topic(ClusterArn=cluster_arn, TopicName=canary_topic)
    _wait_for_topic_gone(ctx, cluster_arn, canary_topic)

    sg = ec2.describe_security_groups(GroupIds=[sg_id])["SecurityGroups"][0]
    saved_permissions = sg["IpPermissions"]
    if not saved_permissions:
        raise AssertionError("the cluster's security group has no ingress rules to revoke")

    # Take every ingress rule off the broker ENIs' security group; the brokers keep running.
    ec2.revoke_security_group_ingress(GroupId=sg_id, IpPermissions=saved_permissions)
    # The measurement starts only once the group reads back with no ingress, so a pass cannot be
    # explained away as "the security group change had not taken effect yet".
    _wait_for_no_ingress(ctx, sg_id, timeout_s=60)

    # The admin path is unaffected: DeleteTopic succeeds with no ingress rule at all.
    kafka.delete_topic(ClusterArn=cluster_arn, TopicName=topic_name)

    # Effect PRESENT, still with ingress revoked: the delete really took.
    _wait_for_topic_gone(ctx, cluster_arn, topic_name, timeout_s=300)
    still_open = ec2.describe_security_groups(GroupIds=[sg_id])["SecurityGroups"][0]["IpPermissions"]
    assert not still_open, (
        f"the security group regained ingress during the measurement, so the delete was not "
        f"observed under a revoked SG: {still_open!r}"
    )

    # Read the topic set back over a second API to confirm both topics are gone. The group is the
    # check's own and its teardown deletes it, so its rules are not restored.
    names = [t["TopicName"] for t in kafka.list_topics(ClusterArn=cluster_arn)["Topics"]]
    assert topic_name not in names and canary_topic not in names, names


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _own_security_group(ctx, vpc_id, cidr, teardown):
    """A security group only this check's cluster uses, since the check revokes its ingress; it admits
    the broker ports from the VPC's CIDR. Its delete retries DependencyViolation while MSK releases
    the broker ENIs, to the shared cleanup deadline."""
    ec2 = ctx.client("ec2")
    sg_id = ec2.create_security_group(
        GroupName=ctx.unique_name("sim2real-behav-msk-sg-"),
        Description="MSK broker access from the cluster VPC",
        VpcId=vpc_id,
    )["GroupId"]

    def _delete():
        deadline = teardown()
        while True:
            try:
                ec2.delete_security_group(GroupId=sg_id)
                return
            except ClientError as exc:
                code = exc.response["Error"]["Code"]
                if code == "InvalidGroup.NotFound":
                    return
                if code != "DependencyViolation" or time.monotonic() >= deadline:
                    raise
            time.sleep(2)

    ctx.on_cleanup(_delete)
    ec2.authorize_security_group_ingress(
        GroupId=sg_id,
        IpPermissions=[{"IpProtocol": "tcp", "FromPort": 9092, "ToPort": 9098, "IpRanges": [{"CidrIp": cidr}]}],
    )
    return sg_id


def _network_subnets_and_sg(ctx, num_azs, teardown):
    ec2 = ctx.client("ec2")
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if not vpcs:
        raise AssertionError("no shared network VPC available to provision an MSK cluster in this account/region")
    vpc_id = vpcs[0]["VpcId"]
    subnets = ec2.describe_subnets(
        Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}]
    )["Subnets"]
    by_az = {}
    for s in subnets:
        by_az.setdefault(s["AvailabilityZone"], s["SubnetId"])
    subnet_ids = list(by_az.values())
    if len(subnet_ids) < num_azs:
        raise AssertionError(f"shared network has fewer than {num_azs} AZ-distinct network subnets")
    return subnet_ids[:num_azs], _own_security_group(ctx, vpc_id, vpcs[0]["CidrBlock"], teardown)


def _active_kafka_version(ctx):
    kafka = ctx.client("kafka")
    versions = kafka.list_kafka_versions().get("KafkaVersions", [])
    # Kafka 4.x is Express-brokers-only; standard (Provisioned) broker instance
    # types like kafka.t3.small are rejected for those versions, so restrict to
    # ACTIVE versions below the 4.x line.
    active = [
        v["Version"]
        for v in versions
        if v.get("Status") == "ACTIVE" and not v["Version"].startswith("4.")
    ]
    if not active:
        raise AssertionError("ListKafkaVersions returned no ACTIVE Kafka version below 4.x")
    return sorted(active, key=lambda s: [int(p) if p.isdigit() else p for p in s.split(".")])[-1]


def _wait_for_cluster_state(ctx, cluster_arn, target_states, timeout_s=1800, interval_s=2):
    kafka = ctx.client("kafka")
    deadline = time.monotonic() + _budget_s(ctx, timeout_s)
    last = None
    while time.monotonic() < deadline:
        info = kafka.describe_cluster_v2(ClusterArn=cluster_arn)["ClusterInfo"]
        last = info.get("State")
        if last in target_states:
            return info
        if last == "FAILED":
            raise AssertionError(f"cluster entered FAILED state while waiting for {target_states}")
        time.sleep(interval_s)
    if _budget_spent(ctx):
        raise TimeoutError(f"cluster {cluster_arn} reaching {target_states}: the run budget ended first; not graded")
    raise AssertionError(f"cluster never reached {target_states}; last observed state={last}")


def _wait_for_cluster_deleted(ctx, cluster_arn, timeout_s=1800, interval_s=20):
    from botocore.exceptions import ClientError

    kafka = ctx.client("kafka")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            kafka.describe_cluster_v2(ClusterArn=cluster_arn)
        except ClientError as err:
            if err.response["Error"]["Code"] == "NotFoundException":
                return
            raise
        time.sleep(interval_s)
    raise AssertionError(f"cluster {cluster_arn} was not deleted within {timeout_s}s")


def _create_provisioned_cluster(ctx, num_brokers=2):
    kafka = ctx.client("kafka")
    deadline = []

    def _teardown_deadline():
        """The shared cleanup deadline, counted from the first teardown that asks for it."""
        if not deadline:
            deadline.append(time.monotonic() + _CLEANUP_BUDGET_S)
        return deadline[0]

    subnets, sg_id = _network_subnets_and_sg(ctx, num_brokers, _teardown_deadline)
    kafka_version = _active_kafka_version(ctx)
    name = ctx.unique_name("sim2real-behav-msk-")
    resp = kafka.create_cluster_v2(
        ClusterName=name,
        Provisioned={
            "BrokerNodeGroupInfo": {
                "InstanceType": "kafka.m5.large",
                "ClientSubnets": subnets,
                "SecurityGroups": [sg_id],
                "StorageInfo": {"EbsStorageInfo": {"VolumeSize": 1}},
            },
            "KafkaVersion": kafka_version,
            "NumberOfBrokerNodes": num_brokers,
        },
    )
    cluster_arn = resp["ClusterArn"]

    def _cleanup():
        try:
            kafka.delete_cluster(ClusterArn=cluster_arn)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NotFoundException":
                raise
            return
        try:
            _wait_for_cluster_deleted(ctx, cluster_arn, timeout_s=_teardown_deadline() - time.monotonic())
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NotFoundException":
                raise

    ctx.on_cleanup(_cleanup)
    # 1800s is too tight: a 2-broker kafka.m5.large provisioned cluster can still be CREATING then.
    _wait_for_cluster_state(ctx, cluster_arn, {"ACTIVE"}, timeout_s=2700)
    return cluster_arn, subnets, sg_id


def _wait_for_topic_status(ctx, cluster_arn, topic_name, target_states, timeout_s=180, interval_s=1):
    from botocore.exceptions import ClientError

    kafka = ctx.client("kafka")
    deadline = time.monotonic() + _budget_s(ctx, timeout_s)
    last = None
    while time.monotonic() < deadline:
        try:
            info = kafka.describe_topic(ClusterArn=cluster_arn, TopicName=topic_name)
        except ClientError as err:
            # CreateTopic returns before DescribeTopic can resolve the topic, so a NotFound here
            # is "not yet", not a verdict.
            if err.response["Error"]["Code"] != "NotFoundException":
                raise
            time.sleep(interval_s)
            continue
        last = info.get("Status")
        if last in target_states:
            return info
        time.sleep(interval_s)
    if _budget_spent(ctx):
        raise TimeoutError(f"topic {topic_name} reaching {target_states}: the run budget ended first; not graded")
    raise AssertionError(f"topic {topic_name} never reached {target_states}; last status={last}")


def _create_topic(ctx, cluster_arn, partitions=1, replication_factor=2):
    kafka = ctx.client("kafka")
    topic_name = ctx.unique_name("sim2real-behav-topic-")
    kafka.create_topic(
        ClusterArn=cluster_arn,
        TopicName=topic_name,
        PartitionCount=partitions,
        ReplicationFactor=replication_factor,
    )
    _wait_for_topic_status(ctx, cluster_arn, topic_name, {"ACTIVE"})
    return topic_name


def _wait_for_no_ingress(ctx, sg_id, timeout_s=60, interval_s=1):
    """RevokeSecurityGroupIngress is eventually consistent in DescribeSecurityGroups, so the
    measurement below waits for the group to actually read back empty."""
    ec2 = ctx.client("ec2")
    deadline = time.monotonic() + _budget_s(ctx, timeout_s)
    last = None
    while time.monotonic() < deadline:
        last = ec2.describe_security_groups(GroupIds=[sg_id])["SecurityGroups"][0]["IpPermissions"]
        if not last:
            return
        time.sleep(interval_s)
    if _budget_spent(ctx):
        raise TimeoutError(f"security group {sg_id} reading back with no ingress: the run budget ended first; not graded")
    raise AssertionError(f"security group {sg_id} still reports ingress rules {last!r}")


def _wait_for_topic_gone(ctx, cluster_arn, topic_name, timeout_s=180, interval_s=1):
    kafka = ctx.client("kafka")
    deadline = time.monotonic() + _budget_s(ctx, timeout_s)
    while time.monotonic() < deadline:
        try:
            kafka.describe_topic(ClusterArn=cluster_arn, TopicName=topic_name)
        except ClientError as err:
            if err.response["Error"]["Code"] == "NotFoundException":
                return
            raise
        time.sleep(interval_s)
    if _budget_spent(ctx):
        raise TimeoutError(f"topic {topic_name} being removed after DeleteTopic: the run budget ended first; not graded")
    raise AssertionError(f"topic {topic_name} was never removed after DeleteTopic")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
