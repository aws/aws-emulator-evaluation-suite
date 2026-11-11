"""update-replication-info-nonexistent-replicator-rejected."""
from __future__ import annotations

import uuid

from behavioral_harness import tags

CHECK = "update-replication-info-nonexistent-replicator-rejected"
GROUP = "overly-permissive"
SERVICES = ["kafka"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """UpdateReplicationInfo against a replicator ARN that does not exist fails with BadRequestException
    and its exact message, and DescribeReplicator on that ARN fails with NotFoundException."""
    kafka = ctx.client("kafka")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]

    # Positive control: the service is reachable and normal read calls succeed.
    listed = kafka.list_replicators()
    assert "Replicators" in listed, f"expected ListReplicators to return a Replicators key, got keys={list(listed)!r}"

    bogus_replicator_arn = (
        f"arn:aws:kafka:{ctx.region}:{account_id}:replicator/"
        f"{ctx.unique_name('nonexistent-replicator-')}/{uuid.uuid4()}"
    )

    topic_replication = {
        "CopyAccessControlListsForTopics": False,
        "CopyTopicConfigurations": False,
        "DetectAndCopyNewTopics": False,
        "TopicsToExclude": [],
        "TopicsToReplicate": [".*"],
    }

    code = _error_code(
        lambda: kafka.update_replication_info(
            ReplicatorArn=bogus_replicator_arn,
            CurrentVersion="1",
            TopicReplication=topic_replication,
        )
    )
    expected_update = (
        "BadRequestException",
        "Must specify either sourceKafkaClusterArn or sourceKafkaClusterId for the source cluster.",
    )
    assert code == expected_update, f"expected {expected_update!r}, got {code!r}"
    # Effect absent: no replicator was implicitly created for this ARN -- a direct
    # describe of the same ARN independently reports NotFoundException.
    code_describe = _error_code(
        lambda: kafka.describe_replicator(ReplicatorArn=bogus_replicator_arn)
    )
    expected_describe = (
        "NotFoundException",
        "Invalid parameter replicatorArn: The requested resource doesn\u2019t exist.",
    )
    assert code_describe == expected_describe, f"expected {expected_describe!r}, got {code_describe!r}"


def _error_code(fn):
    """Call fn(); return the botocore (Error.Code, Error.Message) of the ClientError it raises. An
    unexpected SUCCESS raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"]["Message"]
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
