"""channel-lifecycle."""
from __future__ import annotations

import time
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "channel-lifecycle"
GROUP = 'overly-permissive'
SERVICES = ['kafka']


def _err(fn):
    """Call fn(); return the botocore Error.Code of the ClientError it raises. A success raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {}).get("Code")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


def _account_id(ctx):
    if not hasattr(ctx, "_kafka_account_id"):
        ctx._kafka_account_id = ctx.client("sts").get_caller_identity()["Account"]
    return ctx._kafka_account_id


def _region(ctx):
    return getattr(ctx, "region", None) or "us-west-2"


def _bogus_cluster_arn(ctx):
    name = ctx.unique_name("sim2real-behav-ghost-cluster-")
    return f"arn:aws:kafka:{_region(ctx)}:{_account_id(ctx)}:cluster/{name}/{uuid.uuid4()}-2"


def _default_vpc_subnets_multi_az(ctx, count=3):
    ec2 = ctx.client("ec2")
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if not vpcs:
        raise AssertionError(f"the run's shared network {ctx.network().vpc_id} is not visible")
    vpc_id = vpcs[0]["VpcId"]
    subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}])["Subnets"]
    by_az: dict[str, str] = {}
    for s in subnets:
        by_az.setdefault(s["AvailabilityZone"], s["SubnetId"])
    subnet_ids = list(by_az.values())
    if len(subnet_ids) < count:
        raise AssertionError(
            f"fewer than {count} distinct-AZ subnets in the shared network; Express brokers require {count} AZs"
        )
    return subnet_ids[:count]


def _create_active_msk_cluster(ctx, timeout_s=2400.0):
    """A real ACTIVE Express-broker cluster: Channels are only supported on Express brokers,
    so this is the positive control that a fake ClusterArn is compared against."""
    kafka = ctx.client("kafka")
    subnets = _default_vpc_subnets_multi_az(ctx, count=3)
    versions = kafka.list_kafka_versions().get("KafkaVersions", [])
    if not versions:
        raise AssertionError("no Kafka versions available to create the positive-control cluster")

    def _key(v):
        # ZooKeeper versions before KRaft ones, then newest first; a "x" patch level sorts high.
        parts = v["Version"].split(".")
        numbers = tuple(int(p) if p.isdigit() else 99 for p in parts[:3])
        return ("kraft" not in parts, numbers)

    versions.sort(key=_key, reverse=True)
    # Express brokers reject every DEPRECATED Kafka version.
    versions = [v for v in versions if v.get("Status") == "ACTIVE"]
    name = ctx.unique_name("sim2real-behav-chan-cluster-")
    # Express instance types are only accepted via CreateClusterV2, and not every Kafka version
    # accepts them (some newest entries reject "Express" with a BadRequestException) -- probe
    # candidates newest-first rather than assuming the first version returned works.
    cluster_arn = None
    last_bad_request = None
    for v in versions[:6]:
        try:
            resp = kafka.create_cluster_v2(
                ClusterName=name,
                Tags={"sim2real-check": CHECK},
                Provisioned={
                    "KafkaVersion": v["Version"],
                    "NumberOfBrokerNodes": 3,
                    "BrokerNodeGroupInfo": {
                        "InstanceType": "express.m7g.large",
                        "ClientSubnets": subnets,
                    },
                },
            )
            cluster_arn = resp["ClusterArn"]
            break
        except ClientError as e:
            msg = e.response["Error"].get("Message", "")
            if e.response["Error"]["Code"] == "BadRequestException" and "not supported for Kafka version" in msg:
                last_bad_request = e
                continue
            raise
    if cluster_arn is None:
        raise AssertionError(
            f"no available Kafka version supports Express instance types via CreateClusterV2: {last_bad_request}"
        )

    def _cleanup():
        try:
            info = kafka.describe_cluster_v2(ClusterArn=cluster_arn)["ClusterInfo"]
            if info["State"] not in ("DELETING",):
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
            time.sleep(15)
        raise AssertionError(f"cluster {cluster_arn} still exists {timeout_s}s after DeleteCluster")

    ctx.on_cleanup(_cleanup)

    deadline = time.monotonic() + timeout_s
    state = "CREATING"
    while time.monotonic() < deadline:
        state = kafka.describe_cluster_v2(ClusterArn=cluster_arn)["ClusterInfo"]["State"]
        if state in ("ACTIVE", "FAILED"):
            break
        time.sleep(2)
    if state != "ACTIVE":
        raise AssertionError(f"positive-control cluster did not reach ACTIVE within {timeout_s}s (state={state})")
    return cluster_arn


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Every Channel operation on a nonexistent ClusterArn fails with NotFoundException.

    ListChannels on a real ACTIVE cluster succeeds, ruling out the Channel API being unavailable."""
    msk = ctx.client("kafka")
    for op in ("create_channel", "describe_channel", "update_channel",
               "delete_channel", "list_channels"):
        if not hasattr(msk, op):
            raise AssertionError(f"botocore kafka client has no {op} operation")

    real_cluster = _create_active_msk_cluster(ctx)
    positive = msk.list_channels(ClusterArn=real_cluster)
    assert positive.get("Channels", []) == [], (
        f"expected ListChannels on a freshly created, real, ACTIVE cluster to succeed with no "
        f"channels, got {positive.get('Channels')!r}"
    )

    region = _region(ctx)
    acct = _account_id(ctx)
    ghost_cluster = _bogus_cluster_arn(ctx)
    ghost_channel = f"arn:aws:kafka:{region}:{acct}:channel/{ctx.unique_name('ghost-')}/{uuid.uuid4()}-5"
    channel_name = ctx.unique_name("sim2real-behav-chan-")
    topic_arn = f"arn:aws:kafka:{region}:{acct}:topic/{ctx.unique_name('ghost-')}/{uuid.uuid4()}-3/sim2real-behav-src-topic"
    topic_configuration = [
        {"TopicArn": topic_arn, "RecordConverter": {"ValueConverter": "JSON"}}
    ]
    s3_destination = {
        "ServiceExecutionRoleArn": f"arn:aws:iam::{acct}:role/{ctx.unique_name('chan-role-')}",
        "DataFreshnessInSeconds": 300,
        "DeadLetterQueueS3": {
            "BucketArn": f"arn:aws:s3:::{ctx.unique_name('chan-dlq-')}",
            "ErrorOutputPrefix": "dlq/",
        },
        "Storage": {
            "BucketArn": f"arn:aws:s3:::{ctx.unique_name('chan-bucket-')}",
            "OutputPrefix": "delivery/",
            "StorageClass": "STANDARD",
            "CompressionType": "GZIP",
        },
    }

    observed = {
        "CreateChannel": _err(
            lambda: msk.create_channel(
                ChannelName=channel_name,
                ClusterArn=ghost_cluster,
                TopicConfigurationList=topic_configuration,
                S3DestinationConfiguration=s3_destination,
            )
        ),
        "DescribeChannel": _err(
            lambda: msk.describe_channel(ChannelArn=ghost_channel, ClusterArn=ghost_cluster)
        ),
        "UpdateChannel": _err(
            lambda: msk.update_channel(ChannelArn=ghost_channel, ClusterArn=ghost_cluster)
        ),
        "DeleteChannel": _err(
            lambda: msk.delete_channel(ChannelArn=ghost_channel, ClusterArn=ghost_cluster)
        ),
        "ListChannels": _err(lambda: msk.list_channels(ClusterArn=ghost_cluster)),
    }
    expected = {
        "CreateChannel": "NotFoundException",
        "DescribeChannel": "NotFoundException",
        "UpdateChannel": "NotFoundException",
        "DeleteChannel": "NotFoundException",
        "ListChannels": "NotFoundException",
    }
    assert observed == expected, f"observed={observed}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
