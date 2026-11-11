"""tag-resource-reserved-key-rejected."""
from __future__ import annotations

import time
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "tag-resource-reserved-key-rejected"
GROUP = 'overly-permissive'
SERVICES = ['kafka']

def _err(fn):
    """Call fn(); return the botocore (Error.Code, Error.Message). A success raises."""
    try:
        result = fn()
    except ClientError as exc:
        error = exc.response.get("Error", {})
        return error.get("Code"), error.get("Message")
    raise AssertionError(f"expected a rejection, but the call succeeded: {result!r}")


def _account_id(ctx):
    if not hasattr(ctx, "_kafka_account_id"):
        ctx._kafka_account_id = ctx.client("sts").get_caller_identity()["Account"]
    return ctx._kafka_account_id


def _fake_cluster_arn(ctx):
    name = ctx.unique_name("sim2real-ghost-cluster-")
    return f"arn:aws:kafka:{ctx.region}:{_account_id(ctx)}:cluster/{name}/{uuid.uuid4()}-2"


def _delete_replicator_settled(kafka, arn, timeout_s=300, interval_s=10):
    """DeleteReplicator refuses a CREATING replicator: retry until it leaves CREATING."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            kafka.delete_replicator(ReplicatorArn=arn)
            return
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "NotFoundException":
                return
            if time.monotonic() >= deadline:
                raise
        time.sleep(interval_s)


def _create_settled_replicator(ctx, timeout_s=900, interval_s=10):
    """The check's own taggable MSK resource: a replicator between two well-formed but
    nonexistent clusters. CreateReplicator validates the clusters asynchronously, so it is
    created in seconds without any network, settles out of CREATING, and can be deleted."""
    kafka = ctx.client("kafka")
    source, target = _fake_cluster_arn(ctx), _fake_cluster_arn(ctx)
    vpc = {"SubnetIds": ["subnet-0a1b2c3d4e5f60718", "subnet-0a1b2c3d4e5f60719"],
           "SecurityGroupIds": ["sg-0a1b2c3d4e5f6071a"]}
    arn = kafka.create_replicator(
        ReplicatorName=ctx.unique_name("sim2real-tagkey-"),
        ServiceExecutionRoleArn=f"arn:aws:iam::{_account_id(ctx)}:role/{ctx.unique_name('sim2real-rrole-')}",
        KafkaClusters=[
            {"AmazonMskCluster": {"MskClusterArn": source}, "VpcConfig": vpc},
            {"AmazonMskCluster": {"MskClusterArn": target}, "VpcConfig": vpc},
        ],
        ReplicationInfoList=[{
            "SourceKafkaClusterArn": source,
            "TargetKafkaClusterArn": target,
            "TargetCompressionType": "NONE",
            "TopicReplication": {"TopicsToReplicate": ["sim2real-.*"]},
            "ConsumerGroupReplication": {"ConsumerGroupsToReplicate": ["sim2real-.*"]},
        }],
        Tags={"sim2real:managed": "true"},
    )["ReplicatorArn"]
    ctx.on_cleanup(lambda: _delete_replicator_settled(kafka, arn))
    deadline = time.monotonic() + timeout_s
    state = None
    while time.monotonic() < deadline:
        state = kafka.describe_replicator(ReplicatorArn=arn)["ReplicatorState"]
        if state != "CREATING":
            return arn
        time.sleep(interval_s)
    raise AssertionError(f"replicator {arn} still {state} after {timeout_s}s")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """TagResource on a replicator accepts an ordinary key but fails a key with the reserved "aws:" prefix
    with BadRequestException and its exact message, and only the ordinary tag is stored."""
    msk = ctx.client("kafka")
    arn = _create_settled_replicator(ctx)

    msk.tag_resource(ResourceArn=arn, Tags={"positive-control": "ok"})
    tags_after_control = msk.list_tags_for_resource(ResourceArn=arn)["Tags"]
    assert tags_after_control.get("positive-control") == "ok", tags_after_control

    err = _err(lambda: msk.tag_resource(ResourceArn=arn, Tags={"aws:reserved": "nope"}))
    expected = (
        "BadRequestException",
        "Invalid tag key. Customers cannot set tag keys starting with aws: (case insensitive)",
    )
    assert err == expected, f"expected {expected!r}, got {err!r}"

    # The rejected tag must not have been stored, and the earlier valid tag
    # must still be there -- the rejection was specific, not a wipe.
    tags = msk.list_tags_for_resource(ResourceArn=arn)["Tags"]
    assert "aws:reserved" not in tags, tags
    assert tags.get("positive-control") == "ok", tags

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
