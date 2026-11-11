"""channel-update-unicode-fields-round-trip."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "channel-update-unicode-fields-round-trip"
GROUP = "representation"
SERVICES = ["kafka"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DescribeChannel returns a channel's unicode tag value, name and S3 output prefix unchanged before
    and after an UpdateChannel that sets DataFreshnessInSeconds to 600, and returns the new value."""
    kafka = ctx.client("kafka")
    s3 = ctx.client("s3")
    iam = ctx.client("iam")

    cluster_arn = _create_express_cluster(ctx, kafka)
    bucket_name = _create_bucket(ctx, s3)
    role_arn = _create_channel_role(ctx, iam, bucket_name)

    topic_name = ctx.unique_name("sim2real-channel-topic-")
    kafka.create_topic(ClusterArn=cluster_arn, TopicName=topic_name, PartitionCount=1, ReplicationFactor=2)
    ctx.on_cleanup(lambda: _delete_topic(kafka, cluster_arn, topic_name))
    topic_arn = _wait_topic_active(kafka, cluster_arn, topic_name)["TopicArn"]

    unicode_channel_name = ctx.unique_name("sim2real-uni-chan-")
    unicode_prefix = "logger/donnees-zhongwen/"
    unicode_tags = {"sim2real-unicode": "\u30ed\u30ac\u30fc donn\u00e9es \u4e2d\u6587"}

    create_resp = _when_channel_ready(lambda: kafka.create_channel(
        ClusterArn=cluster_arn,
        ChannelName=unicode_channel_name,
        TopicConfigurationList=[{"TopicArn": topic_arn, "RecordConverter": {"ValueConverter": "STRING"}}],
        S3DestinationConfiguration={
            "DataFreshnessInSeconds": 300,
            "ServiceExecutionRoleArn": role_arn,
            "DeadLetterQueueS3": {"BucketArn": f"arn:aws:s3:::{bucket_name}", "ErrorOutputPrefix": "dlq/"},
            "Storage": {
                "BucketArn": f"arn:aws:s3:::{bucket_name}",
                "OutputPrefix": unicode_prefix,
                "StorageClass": "STANDARD",
                "CompressionType": "NONE",
            },
        },
        Tags=unicode_tags,
    ))
    channel_arn = create_resp["ChannelArn"]
    ctx.on_cleanup(lambda: _delete_channel_and_wait(kafka, cluster_arn, channel_arn))
    _wait_channel_status(kafka, cluster_arn, channel_arn, {"ACTIVE"}, {"FAILED"})

    before = kafka.describe_channel(ClusterArn=cluster_arn, ChannelArn=channel_arn)
    assert before["ChannelName"] == unicode_channel_name
    assert before["S3DestinationConfiguration"]["Storage"]["OutputPrefix"] == unicode_prefix
    assert before.get("Tags") == unicode_tags, f"unicode tag not read back intact: {before.get('Tags')!r}"

    update_resp = kafka.update_channel(
        ClusterArn=cluster_arn, ChannelArn=channel_arn, S3DestinationUpdate={"DataFreshnessInSeconds": 600}
    )
    _wait_cluster_operation_ok(kafka, update_resp.get("ClusterOperationArn"))
    _wait_channel_status(kafka, cluster_arn, channel_arn, {"ACTIVE"}, {"FAILED"})

    after = kafka.describe_channel(ClusterArn=cluster_arn, ChannelArn=channel_arn)
    assert after["ChannelName"] == unicode_channel_name, (
        f"unicode channel name changed after an unrelated update: {after['ChannelName']!r}"
    )
    assert after["S3DestinationConfiguration"]["Storage"]["OutputPrefix"] == unicode_prefix, (
        f"unicode S3 output prefix changed after an unrelated update: "
        f"{after['S3DestinationConfiguration']['Storage']['OutputPrefix']!r}"
    )
    assert after.get("Tags") == unicode_tags, (
        f"unicode tag value changed after an unrelated update: {after.get('Tags')!r}"
    )
    assert after["S3DestinationConfiguration"]["DataFreshnessInSeconds"] == 600


def _delete_topic(kafka, cluster_arn, topic_name):
    try:
        kafka.delete_topic(ClusterArn=cluster_arn, TopicName=topic_name)
    except ClientError as e:
        if e.response["Error"]["Code"] != "NotFoundException":
            raise


def _wait_topic_active(kafka, cluster_arn, topic_name, timeout_s=300.0, interval_s=10.0):
    """CreateTopic returns while the topic is CREATING, and the topic APIs "reflect data that
    updates approximately every minute"
    (https://docs.aws.amazon.com/msk/1.0/apireference/clusters-clusterarn-topics.html)."""
    deadline = time.monotonic() + timeout_s
    status = None
    while time.monotonic() < deadline:
        try:
            info = kafka.describe_topic(ClusterArn=cluster_arn, TopicName=topic_name)
        except ClientError as e:
            if e.response["Error"]["Code"] != "NotFoundException":
                raise
            info = {}
        status = info.get("Status")
        if status == "ACTIVE":
            return info
        time.sleep(interval_s)
    raise AssertionError(f"topic {topic_name} never reached ACTIVE within {timeout_s}s (last {status!r})")


def _when_channel_ready(call, timeout_s=300.0, interval_s=15.0):
    """CreateChannel answered BadRequestException "Topic ... does not exist" for an ACTIVE topic on
    real AWS while the channel service had not yet seen it, and ForbiddenException "Unable to assume
    the channel's service execution role" for a just-created role; both are readiness, so they
    are retried, bounded. Anything else returns."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return call()
        except ClientError as e:
            message = e.response["Error"].get("Message", "").lower()
            readiness = e.response["Error"]["Code"] in ("BadRequestException", "ForbiddenException") and (
                "does not exist" in message or "assume" in message
            )
            if not readiness or time.monotonic() >= deadline:
                raise
        time.sleep(interval_s)


def _express_version_candidates(kafka) -> list[str]:
    """Every Kafka version, ordered so an Express-eligible one is tried first.

    ListKafkaVersions is PAGINATED and its ACTIVE set mixes two broker categories, so
    neither `sorted(...)[-1]` nor a numeric "newest first" sort lands on an Express-eligible
    entry: measured on real AWS, `sorted(...)[-1]` picks "4.2.x.kraft" and a numeric key ranks
    the legacy dotted versions (3.6.0.1, ...) first because the lettered ones fail int() and
    fall back to a low sentinel. AWS's own rejection names the eligible set as e.g.
    "3.8.x, 3.9.x.kraft, 4.2.x.kraft" -- every eligible string carries a letter -- so try all
    lettered versions before any numeric-only one, newest-looking first within each group.
    """
    versions = []
    for page in kafka.get_paginator("list_kafka_versions").paginate():
        versions.extend(page.get("KafkaVersions", []))
    if not versions:
        raise AssertionError("ListKafkaVersions returned no versions")

    def _key(v):
        version = v["Version"]
        has_letter = any(c.isalpha() for c in version)
        try:
            numeric = tuple(int(p) for p in version.split("."))
        except ValueError:
            numeric = ()
        return (has_letter, numeric)

    versions.sort(key=_key, reverse=True)
    # Dedupe: ListKafkaVersions returns some versions twice (once ACTIVE, once DEPRECATED).
    seen, ordered = set(), []
    for v in versions:
        if v["Version"] not in seen:
            seen.add(v["Version"])
            ordered.append(v["Version"])
    return ordered


def _create_express_cluster(ctx, kafka, timeout_s=3600.0, interval_s=20.0):
    # Express brokers require three subnets in distinct zones.
    subnet_ids = ctx.network().subnet_ids[:3]
    name = ctx.unique_name("sim2real-mskx-")
    # Probe candidates through the real CreateClusterV2 call rather than assuming any one entry
    # is usable: versions reserved for a different broker category reject Express instance types
    # with a BadRequestException. Express brokers also manage their own storage, so no
    # StorageInfo is sent, and the default SG is left implicit (the Channel assertions below are
    # control-plane only and never dial a broker).
    cluster_arn = None
    errors_by_version = {}
    for version in _express_version_candidates(kafka):
        try:
            resp = kafka.create_cluster_v2(
                ClusterName=name,
                Provisioned={
                    "BrokerNodeGroupInfo": {
                        "InstanceType": "express.m7g.large",
                        "ClientSubnets": subnet_ids,
                    },
                    "KafkaVersion": version,
                    "NumberOfBrokerNodes": len(subnet_ids),
                },
            )
            cluster_arn = resp["ClusterArn"]
            break
        except ClientError as e:
            if e.response.get("Error", {}).get("Code") != "BadRequestException":
                raise
            errors_by_version[version] = e.response["Error"].get("Message", "")
    if cluster_arn is None:
        raise AssertionError(
            f"CreateClusterV2 refused every Kafka version for an Express cluster: {errors_by_version}"
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


def _delete_cluster_and_wait(kafka, cluster_arn, timeout_s=900.0, interval_s=20.0):
    try:
        kafka.delete_cluster(ClusterArn=cluster_arn)
    except ClientError as e:
        if e.response["Error"]["Code"] == "NotFoundException":
            return
        raise
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            kafka.describe_cluster_v2(ClusterArn=cluster_arn)
        except ClientError as e:
            if e.response["Error"]["Code"] == "NotFoundException":
                return
            raise
        time.sleep(interval_s)
    raise AssertionError(f"cluster {cluster_arn} still present {timeout_s}s after DeleteCluster")


def _create_bucket(ctx, s3):
    bucket_name = ctx.unique_name("sim2real-msk-channel-")
    region = ctx.region
    if region == "us-east-1":
        s3.create_bucket(Bucket=bucket_name)
    else:
        s3.create_bucket(Bucket=bucket_name, CreateBucketConfiguration={"LocationConstraint": region})
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(s3, bucket_name))
    return bucket_name


def _empty_and_delete_bucket(s3, bucket_name):
    try:
        paginator = s3.get_paginator("list_objects_v2")
        for page in paginator.paginate(Bucket=bucket_name):
            keys = [{"Key": o["Key"]} for o in page.get("Contents", [])]
            if keys:
                failed = s3.delete_objects(Bucket=bucket_name, Delete={"Objects": keys}).get("Errors")
                if failed:
                    raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
        s3.delete_bucket(Bucket=bucket_name)
    except ClientError as e:
        if e.response["Error"]["Code"] != "NoSuchBucket":
            raise


def _create_channel_role(ctx, iam, bucket_name):
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": "kafka.amazonaws.com"}, "Action": "sts:AssumeRole"}],
    }
    role_name = ctx.unique_name("sim2real-msk-channel-role-")
    role_arn = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust_policy))["Role"]["Arn"]
    ctx.on_cleanup(lambda: _delete_role(iam, role_name))
    inline_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                # CreateChannel checks s3:GetBucketLocation on the bucket.
                "Action": ["s3:PutObject", "s3:GetObject", "s3:ListBucket", "s3:GetBucketLocation"],
                "Resource": [f"arn:aws:s3:::{bucket_name}", f"arn:aws:s3:::{bucket_name}/*"],
            }
        ],
    }
    policy_name = "sim2real-msk-channel-s3-access"
    iam.put_role_policy(RoleName=role_name, PolicyName=policy_name, PolicyDocument=json.dumps(inline_policy))
    ctx.on_cleanup(lambda: _delete_role_policy(iam, role_name, policy_name))
    return role_arn


def _delete_role(iam, role_name):
    try:
        iam.delete_role(RoleName=role_name)
    except iam.exceptions.NoSuchEntityException:
        pass


def _delete_role_policy(iam, role_name, policy_name):
    try:
        iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name)
    except iam.exceptions.NoSuchEntityException:
        pass


def _wait_channel_status(kafka, cluster_arn, channel_arn, success_states, failure_states, timeout_s=900.0, interval_s=15.0):
    deadline = time.monotonic() + timeout_s
    status = None
    while time.monotonic() < deadline:
        status = kafka.describe_channel(ClusterArn=cluster_arn, ChannelArn=channel_arn)["Status"]
        if status in success_states:
            return
        if status in failure_states:
            raise AssertionError(f"channel {channel_arn} entered {status}")
        time.sleep(interval_s)
    raise AssertionError(f"channel {channel_arn} did not settle within {timeout_s}s, last status {status!r}")


def _wait_cluster_operation_ok(kafka, operation_arn, timeout_s=900.0, interval_s=15.0):
    if not operation_arn:
        return
    deadline = time.monotonic() + timeout_s
    state = None
    while time.monotonic() < deadline:
        state = kafka.describe_cluster_operation_v2(ClusterOperationArn=operation_arn)["ClusterOperationInfo"][
            "OperationState"
        ]
        # A channel update's cluster operation ends COMPLETED.
        if state in ("UPDATE_COMPLETE", "COMPLETED"):
            return
        if state in ("UPDATE_FAILED", "FAILED"):
            raise AssertionError(f"cluster operation {operation_arn} failed")
        time.sleep(interval_s)
    raise AssertionError(f"cluster operation {operation_arn} did not complete within {timeout_s}s, last {state!r}")


def _delete_channel_and_wait(kafka, cluster_arn, channel_arn, timeout_s=900.0, interval_s=15.0):
    deadline = time.monotonic() + timeout_s
    # DeleteChannel is refused while the channel is CREATING ("Channel must be in ACTIVE, FAILED,
    # or SUSPENDED state to be deleted"), so it is let settle first.
    while time.monotonic() < deadline:
        try:
            status = kafka.describe_channel(ClusterArn=cluster_arn, ChannelArn=channel_arn).get("Status")
        except ClientError as e:
            if e.response["Error"]["Code"] == "NotFoundException":
                return
            raise
        if status in ("ACTIVE", "FAILED", "SUSPENDED", "DELETING"):
            break
        time.sleep(interval_s)
    try:
        kafka.delete_channel(ClusterArn=cluster_arn, ChannelArn=channel_arn)
    except ClientError as e:
        if e.response["Error"]["Code"] == "NotFoundException":
            return
        raise
    while time.monotonic() < deadline:
        try:
            kafka.describe_channel(ClusterArn=cluster_arn, ChannelArn=channel_arn)
        except ClientError as e:
            if e.response["Error"]["Code"] == "NotFoundException":
                return
            raise
        time.sleep(interval_s)
    raise AssertionError(f"channel {channel_arn} still present {timeout_s}s into its teardown")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
