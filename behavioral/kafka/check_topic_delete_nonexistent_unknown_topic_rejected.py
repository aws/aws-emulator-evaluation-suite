"""topic-delete-nonexistent-unknown-topic-rejected."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "topic-delete-nonexistent-unknown-topic-rejected"
GROUP = "error-semantics"
SERVICES = ["kafka"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteTopic fails with NotFoundException for a nonexistent cluster and for a never-created topic on
    an ACTIVE cluster, which stays ACTIVE, while a real topic on the same cluster deletes cleanly."""
    kafka = ctx.client("kafka")

    # A nonexistent ClusterArn must be scoped to the caller's own account -- a made-up account id
    # (e.g. the docs placeholder 123456789012) makes this a cross-account request, which real AWS
    # rejects with an authorization error rather than NotFoundException, regardless of whether the
    # resource is real.
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    phantom_cluster_arn = (
        f"arn:aws:kafka:{ctx.region}:{account_id}:cluster/"
        f"{ctx.unique_name('sim2real-ghost-cluster-')}/00000000-0000-0000-0000-000000000000-1"
    )
    cluster_missing_code = _error_code(
        lambda: kafka.delete_topic(ClusterArn=phantom_cluster_arn, TopicName="whatever")
    )
    assert cluster_missing_code == _NOT_FOUND, (
        f"expected {_NOT_FOUND!r} for a nonexistent ClusterArn, got {cluster_missing_code!r}"
    )

    cluster_arn = _create_active_provisioned_cluster(ctx, num_brokers=2)

    # DeleteTopic's control plane does not surface the Kafka broker's protocol-level
    # UnknownTopicOrPartitionException for a topic that never existed on a real cluster -- it maps
    # the miss onto the same modelled NotFoundException a nonexistent ClusterArn gets, with the
    # same generic message, so the two calls above are not distinguishable by code or message
    # alone. What DOES distinguish them is the cluster itself: this ClusterArn is independently
    # proven to resolve (we just created it and waited for ACTIVE), while the phantom ARN above
    # was never created at all.
    ghost_topic = ctx.unique_name("sim2real-ghost-topic-")
    code = _error_code(lambda: kafka.delete_topic(ClusterArn=cluster_arn, TopicName=ghost_topic))
    assert code == _NOT_FOUND, f"expected {_NOT_FOUND!r}, got {code!r}"

    # the real cluster still resolves and is healthy -- the NotFoundException above was scoped to
    # the topic, not the cluster, unlike the phantom-ClusterArn case
    still_active = kafka.describe_cluster_v2(ClusterArn=cluster_arn)["ClusterInfo"]["State"]
    assert still_active == "ACTIVE", f"expected the real cluster to still be ACTIVE, got {still_active}"

    # the never-created topic still doesn't exist after the failed delete attempt
    still_missing = _error_code(lambda: kafka.describe_topic(ClusterArn=cluster_arn, TopicName=ghost_topic))
    assert still_missing == _NOT_FOUND, still_missing

    # positive control: a real topic on the same cluster deletes cleanly
    real_topic = ctx.unique_name("sim2real-real-topic-")
    kafka.create_topic(ClusterArn=cluster_arn, TopicName=real_topic, PartitionCount=1, ReplicationFactor=1)
    ctx.on_cleanup(lambda: _best_effort(lambda: kafka.delete_topic(ClusterArn=cluster_arn, TopicName=real_topic)))
    _wait_for_topic_status(ctx, cluster_arn, real_topic, "ACTIVE")
    kafka.delete_topic(ClusterArn=cluster_arn, TopicName=real_topic)
    _wait_for_topic_gone(ctx, cluster_arn, real_topic)


def _error_code(fn):
    """Call fn(); return the botocore (Error.Code, Error.Message). A success raises."""
    from botocore.exceptions import ClientError
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"]["Message"]
    raise AssertionError(f"expected a rejection, but the call succeeded: {result!r}")


# MSK's message for a topic or cluster that resolves to nothing (U+2019 apostrophe).
_NOT_FOUND = ("NotFoundException", "The requested resource doesn\u2019t exist.")


def _best_effort(fn):
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NotFoundException":
            raise


def _default_vpc_subnets_and_sg(ctx):
    ec2 = ctx.client("ec2")
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if not vpcs:
        raise AssertionError(f"the run's shared network {ctx.network().vpc_id} is not visible")
    vpc_id = vpcs[0]["VpcId"]
    subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}])["Subnets"]
    by_az = {}
    for s in subnets:
        by_az.setdefault(s["AvailabilityZone"], s["SubnetId"])
    subnet_ids = list(by_az.values())[:2]
    if len(subnet_ids) < 2:
        raise AssertionError("need subnets in >=2 AZs in the VPC to create an MSK cluster")
    sgs = ec2.describe_security_groups(
        Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "group-name", "Values": ["default"]}]
    )["SecurityGroups"]
    return vpc_id, subnet_ids, sgs[0]["GroupId"]


def _pick_kafka_versions(ctx, minimum=(3, 6, 0)):
    kafka = ctx.client("kafka")
    versions = kafka.list_kafka_versions().get("KafkaVersions", [])

    def _key(ver):
        nums = []
        for p in ver.split("."):
            try:
                nums.append(int(p))
            except ValueError:
                nums.append(0)
        return tuple(nums)

    candidates = sorted(
        (v["Version"] for v in versions if _key(v["Version"]) >= minimum and v.get("Status") != "DEPRECATED"),
        key=_key,
    )
    if not candidates:
        raise AssertionError("no ACTIVE Kafka version >= 3.6.0 available for topic management APIs")
    return candidates


def _wait_for_cluster_active(ctx, cluster_arn, timeout_s=2700.0, interval_s=20.0):
    kafka = ctx.client("kafka")
    deadline = time.monotonic() + timeout_s
    last_state = None
    while time.monotonic() < deadline:
        info = kafka.describe_cluster_v2(ClusterArn=cluster_arn)["ClusterInfo"]
        last_state = info["State"]
        if last_state == "ACTIVE":
            return info
        if last_state == "FAILED":
            raise AssertionError(f"cluster {cluster_arn} entered FAILED state")
        time.sleep(interval_s)
    raise AssertionError(f"cluster {cluster_arn} did not reach ACTIVE within {timeout_s}s (last={last_state})")


def _create_active_provisioned_cluster(ctx, *, num_brokers=2, instance_type="kafka.t3.small",
                                        client_authentication=None, security_group_ids=None):
    from botocore.exceptions import ClientError

    kafka = ctx.client("kafka")
    _, subnet_ids, default_sg = _default_vpc_subnets_and_sg(ctx)
    # CreateCluster requires two or three ClientSubnets, and NumberOfBrokerNodes must be a
    # multiple of the number of Availability Zones in those subnets -- both measured on real AWS
    # (BadRequestException: "Specify either two or three client subnets"; "...the target number
    # of brokers must be a multiple of [the AZ count]"). Two subnets means two is the smallest
    # broker count CreateCluster will accept; there is no smaller, faster-provisioning shape.
    broker_subnets = subnet_ids
    candidates = _pick_kafka_versions(ctx)
    name = ctx.unique_name("sim2real-msk-")
    cluster_arn = None
    last_bad_request = None
    # The lowest ACTIVE version >= 3.6.0 is sometimes still reserved for a different broker
    # category (e.g. Express-only) and rejects the "Standard" kafka.t3.small instance type with
    # a BadRequestException ("Standard instance types are not supported for Kafka version
    # ..."); probe candidates ascending via the real CreateCluster call instead of assuming the
    # first candidate is always usable.
    for kafka_version in candidates[:6]:
        kwargs = {
            "ClusterName": name,
            "KafkaVersion": kafka_version,
            "NumberOfBrokerNodes": num_brokers,
            "BrokerNodeGroupInfo": {
                "InstanceType": instance_type,
                "ClientSubnets": broker_subnets,
                "SecurityGroups": security_group_ids or [default_sg],
                "StorageInfo": {"EbsStorageInfo": {"VolumeSize": 1}},
            },
            "Tags": {"sim2real:managed": "true"},
        }
        if client_authentication:
            kwargs["ClientAuthentication"] = client_authentication
        try:
            cluster_arn = kafka.create_cluster(**kwargs)["ClusterArn"]
            break
        except ClientError as e:
            msg = e.response["Error"].get("Message", "")
            if e.response["Error"]["Code"] == "BadRequestException" and "not supported for Kafka version" in msg:
                last_bad_request = e
                continue
            raise
    if cluster_arn is None:
        raise AssertionError(
            f"no available Kafka version supports instance type {instance_type} via CreateCluster: {last_bad_request}"
        )
    ctx.on_cleanup(lambda: _best_effort(lambda: kafka.delete_cluster(ClusterArn=cluster_arn)))
    _wait_for_cluster_active(ctx, cluster_arn)
    return cluster_arn


def _wait_for_topic_status(ctx, cluster_arn, topic_name, target_status, timeout_s=180.0, interval_s=5.0):
    kafka = ctx.client("kafka")
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = kafka.describe_topic(ClusterArn=cluster_arn, TopicName=topic_name)
        if last["Status"] == target_status:
            return last
        time.sleep(interval_s)
    raise AssertionError(f"topic {topic_name} never reached {target_status}, last={last}")


def _wait_for_topic_gone(ctx, cluster_arn, topic_name, timeout_s=180.0, interval_s=5.0):
    kafka = ctx.client("kafka")
    deadline = time.monotonic() + timeout_s
    from botocore.exceptions import ClientError
    while time.monotonic() < deadline:
        try:
            kafka.describe_topic(ClusterArn=cluster_arn, TopicName=topic_name)
        except ClientError as err:
            if err.response["Error"]["Code"] == "NotFoundException":
                return
            raise
        time.sleep(interval_s)
    raise AssertionError(f"topic {topic_name} was never removed after DeleteTopic")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
