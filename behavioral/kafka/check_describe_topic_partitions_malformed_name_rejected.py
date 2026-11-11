"""describe-topic-partitions-malformed-name-rejected."""
from __future__ import annotations

import uuid
from urllib.parse import quote

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "describe-topic-partitions-malformed-name-rejected"
GROUP = "error-semantics"
SERVICES = ["kafka"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DescribeTopicPartitions with a ClusterArn outside the "cluster/<name>/<uuid>" shape fails with
    AccessDeniedException and its exact message, while a well-formed but nonexistent cluster ARN fails with
    NotFoundException."""
    kafka = ctx.client("kafka")
    sts = ctx.client("sts")
    caller = sts.get_caller_identity()
    account = caller["Account"]

    topic_name = ctx.unique_name("sim2real-topic-")

    # Malformed: a well-formed ARN prefix (partition/service/region/account all valid) but the
    # cluster resource segment is missing its required "/<uuid>" suffix -- a structurally
    # invalid MSK cluster ARN that can't be resolved to a resource for authorization.
    malformed_cluster_arn = (
        f"arn:aws:kafka:{ctx.region}:{account}:cluster/{ctx.unique_name('sim2real-bogus-')}"
    )

    def _malformed_call():
        kafka.describe_topic_partitions(ClusterArn=malformed_cluster_arn, TopicName=topic_name)

    malformed_code, malformed_message = _error_code(_malformed_call)
    assert malformed_code == "AccessDeniedException", f"got={malformed_code}"
    expected_denial = (
        f"User: {caller['Arn']} is not authorized to perform: kafka-cluster:Connect "
        f"on resource: {quote(malformed_cluster_arn, safe='')}"
    )
    assert malformed_message == expected_denial, f"unexpected message: {malformed_message!r}"

    # Positive control: syntactically valid ARN shape, but the cluster does not exist --
    # authorization succeeds and it fails for the *different* reason (resource not found).
    bogus_cluster_arn = (
        f"arn:aws:kafka:{ctx.region}:{account}:cluster/"
        f"{ctx.unique_name('sim2real-bogus-')}/{uuid.uuid4()}-1"
    )

    def _valid_call():
        kafka.describe_topic_partitions(ClusterArn=bogus_cluster_arn, TopicName=topic_name)

    valid_code, valid_message = _error_code(_valid_call)
    assert valid_code == "NotFoundException", (
        f"expected NotFoundException once the ClusterArn is syntactically valid, got {valid_code!r}"
    )
    assert valid_message == "The requested resource doesn\u2019t exist.", (
        f"unexpected message: {valid_message!r}"
    )


def _error_code(fn):
    """Call fn(); return (Error.Code, Error.Message). An unexpected success raises."""
    try:
        resp = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {resp}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

