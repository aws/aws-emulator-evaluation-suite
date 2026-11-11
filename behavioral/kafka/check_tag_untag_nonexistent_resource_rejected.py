"""tag-untag-nonexistent-resource-rejected."""
from __future__ import annotations

import time
import uuid

from behavioral_harness import tags

CHECK = "tag-untag-nonexistent-resource-rejected"
GROUP = "error-semantics"
SERVICES = ["kafka"]

# Prefixes the failure of a resource the target accepted but never converged to its ready state,
# so it reads as a state-machine failure rather than a connection or not-implemented error.
STATE_MARKER = "TARGET_STATE_UNIMPLEMENTED"


def _never_ready(msg: str):
    """The verdict for a resource that never reached its ready state.

    Returns the exception rather than raising it, so a call site keeps its ``from exc`` chaining.
    """
    return AssertionError(f"{STATE_MARKER}: {msg}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Tag, Untag and ListTagsForResource on a nonexistent MSK ARN are all NotFoundException.

    The identical calls on a real replicator (created fast, settles FAILED, deletable) succeed and
    round-trip the tag, so the refusal is about the phantom resource (positive control).
    """
    kafka = ctx.client("kafka")
    ghost_arn = _fake_cluster_arn(ctx)

    observed = {
        "TagResource": _error(lambda: kafka.tag_resource(ResourceArn=ghost_arn, Tags={"env": "sim2real"})),
        "UntagResource": _error(lambda: kafka.untag_resource(ResourceArn=ghost_arn, TagKeys=["env"])),
        "ListTagsForResource": _error(lambda: kafka.list_tags_for_resource(ResourceArn=ghost_arn)),
    }
    expected = ("NotFoundException", "Resource was not found")
    for op, got in observed.items():
        assert got == expected, f"{op} on a nonexistent ARN: expected {expected!r}, got {got!r}"

    # Positive control: the same three calls succeed against a real MSK resource.
    replicator_arn = _create_settled_replicator(ctx)
    kafka.tag_resource(ResourceArn=replicator_arn, Tags={"env": "sim2real"})
    tags_now = kafka.list_tags_for_resource(ResourceArn=replicator_arn)["Tags"]
    assert tags_now.get("env") == "sim2real", tags_now
    kafka.untag_resource(ResourceArn=replicator_arn, TagKeys=["env"])
    tags_after = kafka.list_tags_for_resource(ResourceArn=replicator_arn)["Tags"]
    assert "env" not in tags_after, tags_after


def _error(fn):
    """Call fn(); return the botocore (Error.Code, Error.Message). An unexpected SUCCESS raises,
    because an emulator ACCEPTING input real AWS refuses is the strongest signal available and
    must not be reported as a mere error-code mismatch."""
    from botocore.exceptions import ClientError
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"]["Message"]
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


def _account_id(ctx):
    if not hasattr(ctx, "_kafka_account_id"):
        ctx._kafka_account_id = ctx.client("sts").get_caller_identity()["Account"]
    return ctx._kafka_account_id


def _fake_cluster_arn(ctx):
    name = ctx.unique_name("sim2real-ghost-cluster-")
    return f"arn:aws:kafka:{ctx.region}:{_account_id(ctx)}:cluster/{name}/{uuid.uuid4()}-2"


def _delete_replicator_settled(kafka, arn, timeout_s=300, interval_s=10):
    """DeleteReplicator refuses a CREATING replicator: retry until it leaves CREATING."""
    from botocore.exceptions import ClientError
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            kafka.delete_replicator(ReplicatorArn=arn)
            return
        except ClientError as err:
            if err.response["Error"]["Code"] == "NotFoundException":
                return
            if time.monotonic() >= deadline:
                raise
        time.sleep(interval_s)


def _create_settled_replicator(ctx, timeout_s=900, interval_s=10):
    """A replicator between two well-formed but nonexistent clusters, polled out of CREATING."""
    kafka = ctx.client("kafka")
    source, target = _fake_cluster_arn(ctx), _fake_cluster_arn(ctx)
    vpc = {"SubnetIds": ["subnet-0a1b2c3d4e5f60718", "subnet-0a1b2c3d4e5f60719"],
           "SecurityGroupIds": ["sg-0a1b2c3d4e5f6071a"]}
    arn = kafka.create_replicator(
        ReplicatorName=ctx.unique_name("sim2real-tagtest-"),
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
    raise _never_ready(f"replicator {arn} still {state} after {timeout_s}s")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
