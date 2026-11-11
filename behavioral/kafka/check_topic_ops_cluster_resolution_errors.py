"""topic-ops-cluster-resolution-errors."""
from __future__ import annotations

import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "topic-ops-cluster-resolution-errors"
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


def _bogus_cluster_arn(ctx):
    """A well-formed MSK cluster ARN, in this account, that cannot exist."""
    name = ctx.unique_name("sim2real-behav-ghost-cluster-")
    return f"arn:aws:kafka:{ctx.region}:{_account_id(ctx)}:cluster/{name}/{uuid.uuid4()}-2"


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateTopic (twice), DescribeTopic and ListTopics against a well-formed but nonexistent ClusterArn
    all fail with NotFoundException and its exact message, never ConflictException."""
    msk = ctx.client("kafka")
    if not hasattr(msk, "create_topic"):
        raise AssertionError("botocore kafka client has no create_topic operation")

    cluster_arn = _bogus_cluster_arn(ctx)
    topic = ctx.unique_name("sim2real-behav-topic-")

    def create_missing():
        return msk.create_topic(
            ClusterArn=cluster_arn,
            TopicName=topic,
            PartitionCount=1,
            ReplicationFactor=2,
        )

    observed = {
        "create_missing_cluster": _err(create_missing),
        "create_missing_cluster_retry": _err(create_missing),
        "describe_topic_missing_cluster": _err(
            lambda: msk.describe_topic(ClusterArn=cluster_arn, TopicName=topic)
        ),
        "list_topics_missing_cluster": _err(
            lambda: msk.list_topics(ClusterArn=cluster_arn)
        ),
    }
    # MSK's message for a cluster ARN that resolves to nothing (U+2019 apostrophe).
    not_found = ("NotFoundException", "The requested resource doesn\u2019t exist.")
    expected = {
        "create_missing_cluster": not_found,
        "create_missing_cluster_retry": not_found,
        "describe_topic_missing_cluster": not_found,
        "list_topics_missing_cluster": not_found,
    }
    assert observed == expected, f"observed={observed}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
