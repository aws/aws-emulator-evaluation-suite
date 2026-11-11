"""delete-topic-cluster-connectivity-exception."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "delete-topic-cluster-connectivity-exception"
GROUP = "error-semantics"
SERVICES = ["kafka"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """MSK's DeleteTopic does not depend on the cluster security group's ingress: with the SG's only
    (self-referencing) ingress rule revoked, DeleteTopic still succeeds and the topic is removed,
    just as it does with the rule in place.

    Reference: https://docs.aws.amazon.com/msk/latest/developerguide/msk-topic-operations.html
    """
    kafka = ctx.client("kafka")
    ec2 = ctx.client("ec2")
    vpc_id, subnet_ids = _default_vpc_subnets(ctx)
    sg_id, self_ref_permission = _create_self_referencing_security_group(ctx, vpc_id)
    cluster_arn = _create_provisioned_cluster(ctx, subnet_ids, sg_id)

    control_topic = ctx.unique_name("sim2real-behav-topic-control-")
    target_topic = ctx.unique_name("sim2real-behav-topic-target-")
    for name in (control_topic, target_topic):
        kafka.create_topic(ClusterArn=cluster_arn, TopicName=name, PartitionCount=1, ReplicationFactor=1)
    ctx.on_cleanup(lambda: _best_effort_delete_topic(kafka, cluster_arn, target_topic))
    _poll_until(
        lambda: [t["TopicName"] for t in kafka.list_topics(ClusterArn=cluster_arn)["Topics"]],
        lambda names: control_topic in names and target_topic in names,
        timeout_s=90,
        ctx=ctx,
    )

    # Positive control: with connectivity intact, deleting a real topic succeeds cleanly.
    kafka.delete_topic(ClusterArn=cluster_arn, TopicName=control_topic)
    _poll_until(
        lambda: [t["TopicName"] for t in kafka.list_topics(ClusterArn=cluster_arn)["Topics"]],
        lambda names: control_topic not in names,
        timeout_s=90,
        ctx=ctx,
    )

    # Cut the SG path a client would use to reach the brokers: revoke the group's only ingress
    # rule, the self-referencing "all traffic from myself" rule, without taking the cluster's
    # ClusterInfo.State offline. The measurement starts only once DescribeSecurityGroups shows no
    # ingress, so a pass cannot be explained by "the change had not landed yet".
    ec2.revoke_security_group_ingress(GroupId=sg_id, IpPermissions=[self_ref_permission])
    ctx.on_cleanup(lambda: _restore_ingress(ec2, sg_id, self_ref_permission))
    _poll_until(
        lambda: ec2.describe_security_groups(GroupIds=[sg_id])["SecurityGroups"][0]["IpPermissions"],
        lambda perms: not perms,
        timeout_s=60,
        ctx=ctx,
    )

    # MEASURED: the admin path is unaffected. DeleteTopic still succeeds with no ingress at all.
    kafka.delete_topic(ClusterArn=cluster_arn, TopicName=target_topic)

    # Effect PRESENT, still with ingress revoked: the delete really took, it was not swallowed.
    _poll_until(
        lambda: [t["TopicName"] for t in kafka.list_topics(ClusterArn=cluster_arn)["Topics"]],
        lambda names: target_topic not in names,
        timeout_s=180,
        ctx=ctx,
    )
    perms_during = ec2.describe_security_groups(GroupIds=[sg_id])["SecurityGroups"][0]["IpPermissions"]
    assert not perms_during, (
        f"the security group regained ingress rules during the measurement, so the topic delete "
        f"was not observed under a revoked SG: {perms_during!r}"
    )

    # Restore, so teardown starts from an intact group.
    ec2.authorize_security_group_ingress(GroupId=sg_id, IpPermissions=[self_ref_permission])


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _poll_until(probe, predicate, *, ctx, timeout_s=60.0, interval_s=1.0):
    timeout_s = _budget_s(ctx, timeout_s)
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    if _budget_spent(ctx):
        raise TimeoutError("topic/security-group wait condition: the run budget ended first; not graded")
    raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")


def _best_effort_delete_topic(kafka, cluster_arn, topic_name):
    from botocore.exceptions import ClientError

    try:
        kafka.delete_topic(ClusterArn=cluster_arn, TopicName=topic_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NotFoundException":
            raise


def _restore_ingress(ec2, sg_id, permission):
    from botocore.exceptions import ClientError

    try:
        ec2.authorize_security_group_ingress(GroupId=sg_id, IpPermissions=[permission])
    except ClientError as exc:
        # Already authorized (restored inline in run()) or the group is already gone.
        if exc.response["Error"]["Code"] not in ("InvalidPermission.Duplicate", "InvalidGroup.NotFound"):
            raise


def _default_vpc_subnets(ctx):
    ec2 = ctx.client("ec2")
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if not vpcs:
        raise AssertionError(f"the run's shared network {ctx.network().vpc_id} is not visible")
    vpc_id = vpcs[0]["VpcId"]
    subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}])["Subnets"]
    by_az: dict[str, str] = {}
    for s in subnets:
        by_az.setdefault(s["AvailabilityZone"], s["SubnetId"])
    subnet_ids = list(by_az.values())[:2]
    if len(subnet_ids) < 2:
        raise AssertionError("shared network does not span >=2 availability zones with subnets")
    return vpc_id, subnet_ids


def _create_self_referencing_security_group(ctx, vpc_id):
    """A dedicated security group whose only ingress rule is "allow all traffic from myself",
    the rule MSK brokers use to reach each other; revoking it cuts SG reachability of the brokers.
    """
    ec2 = ctx.client("ec2")
    name = ctx.unique_name("sim2real-behav-msk-sg-")
    sg_id = ec2.create_security_group(
        GroupName=name,
        Description="sim2real behavioral test SG for MSK connectivity",
        VpcId=vpc_id,
        TagSpecifications=[{"ResourceType": "security-group", "Tags": [{"Key": "Name", "Value": name}]}],
    )["GroupId"]
    ctx.on_cleanup(lambda: _delete_security_group_when_free(ec2, sg_id))
    self_ref_permission = {"IpProtocol": "-1", "UserIdGroupPairs": [{"GroupId": sg_id}]}
    ec2.authorize_security_group_ingress(GroupId=sg_id, IpPermissions=[self_ref_permission])
    return sg_id, self_ref_permission


def _active_kafka_version(ctx):
    """The newest ACTIVE version below 4.x, which is Express-brokers-only.

    Labels like "3.9.x" and "4.1.x.kraft" are not all-numeric, so parts sort as int or str.
    """
    kafka = ctx.client("kafka")
    versions = kafka.list_kafka_versions().get("KafkaVersions", [])
    active = [
        v["Version"]
        for v in versions
        if v.get("Status") == "ACTIVE" and not v["Version"].startswith("4.")
    ]
    if not active:
        raise AssertionError("ListKafkaVersions returned no ACTIVE Kafka version below 4.x")
    return sorted(active, key=lambda s: [int(p) if p.isdigit() else p for p in s.split(".")])[-1]


def _create_provisioned_cluster(ctx, subnet_ids, sg_id):
    """A 2-broker kafka.m5.large provisioned cluster on the dedicated security group."""
    kafka = ctx.client("kafka")
    name = ctx.unique_name("sim2real-behav-kafka-")
    kafka_version = _active_kafka_version(ctx)
    resp = kafka.create_cluster(
        ClusterName=name,
        KafkaVersion=kafka_version,
        NumberOfBrokerNodes=len(subnet_ids),
        BrokerNodeGroupInfo={
            "InstanceType": "kafka.m5.large",
            "ClientSubnets": subnet_ids,
            "SecurityGroups": [sg_id],
            "StorageInfo": {"EbsStorageInfo": {"VolumeSize": 1}},
        },
        Tags={"sim2real:managed": "true"},
    )
    cluster_arn = resp["ClusterArn"]
    ctx.on_cleanup(lambda: kafka.delete_cluster(ClusterArn=cluster_arn))
    _wait_cluster_active(ctx, cluster_arn)
    return cluster_arn


def _wait_cluster_active(ctx, cluster_arn, timeout_s=2700.0, interval_s=2.0):
    # A 2-broker kafka.m5.large cluster can still be CREATING after 1800 s.
    kafka = ctx.client("kafka")
    timeout_s = _budget_s(ctx, timeout_s)
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        info = kafka.describe_cluster(ClusterArn=cluster_arn)["ClusterInfo"]
        state = info["State"]
        if state == "ACTIVE":
            return info
        if state == "FAILED":
            raise AssertionError(f"cluster {cluster_arn} entered FAILED state while provisioning")
        time.sleep(interval_s)
    if _budget_spent(ctx):
        raise TimeoutError(f"cluster {cluster_arn} becoming ACTIVE: the run budget ended first; not graded")
    raise AssertionError(f"cluster {cluster_arn} did not become ACTIVE within {timeout_s}s")



def _delete_security_group_when_free(ec2, sg_id, timeout_s=1500.0, interval_s=15.0):
    """Delete a security group once the broker ENIs holding it are released (DependencyViolation).

    DeleteCluster does not wait, and the broker ENIs can take many minutes to go.
    """
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    while True:
        try:
            ec2.delete_security_group(GroupId=sg_id)
            return
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code == "InvalidGroup.NotFound":
                return
            if code != "DependencyViolation" or time.monotonic() >= deadline:
                raise
            time.sleep(interval_s)

if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
