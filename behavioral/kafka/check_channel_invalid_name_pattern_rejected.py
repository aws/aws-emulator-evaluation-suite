"""channel-invalid-name-pattern-rejected."""
from __future__ import annotations

import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "channel-invalid-name-pattern-rejected"
GROUP = "overly-permissive"
SERVICES = ["kafka"]

_NOT_FOUND_MESSAGE = "The requested resource doesn\u2019t exist."


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateChannel with a ClusterArn outside the "cluster/<name>/<uuid>" shape fails with
    AccessDeniedException on resource "*", while a well-formed but nonexistent cluster ARN fails with
    NotFoundException and its exact message."""
    kafka = ctx.client("kafka")
    sts = ctx.client("sts")
    identity = sts.get_caller_identity()
    account = identity["Account"]

    # Positive control: the client/credentials/service are generally healthy, so the two
    # rejections below cannot be explained by "everything to this service fails".
    kafka.list_kafka_versions()

    bogus_cluster_name = ctx.unique_name("sim2real-bogus-")
    bogus_cluster_uuid = str(uuid.uuid4())
    bogus_cluster_arn = (
        f"arn:aws:kafka:{ctx.region}:{account}:cluster/{bogus_cluster_name}/{bogus_cluster_uuid}-1"
    )
    topic_arn = (
        f"arn:aws:kafka:{ctx.region}:{account}:topic/"
        f"{bogus_cluster_name}/{bogus_cluster_uuid}-1/{ctx.unique_name('sim2real-topic-')}"
    )
    role_arn = f"arn:aws:iam::{account}:role/{ctx.unique_name('sim2real-role-')}"
    bucket_arn = f"arn:aws:s3:::{ctx.unique_name('sim2real-bucket-')}"

    destination = {
        "ServiceExecutionRoleArn": role_arn,
        "Storage": {
            "BucketArn": bucket_arn,
            "StorageClass": "STANDARD",
            "CompressionType": "NONE",
        },
        "DeadLetterQueueS3": {"BucketArn": bucket_arn, "ErrorOutputPrefix": "errors/"},
        "DataFreshnessInSeconds": 60,
    }
    topic_config = [
        {"TopicArn": topic_arn, "RecordConverter": {"ValueConverter": "BYTE_ARRAY"}}
    ]

    # Malformed: a well-formed ARN prefix (partition/service/region/account all valid) but the
    # cluster resource segment is missing its required "/<uuid>" suffix -- a structurally
    # invalid MSK cluster ARN that can't be resolved to a resource for authorization.
    malformed_cluster_arn = f"arn:aws:kafka:{ctx.region}:{account}:cluster/{bogus_cluster_name}"
    malformed_name = ctx.unique_name("sim2real-ch-")

    def _malformed_call():
        return kafka.create_channel(
            ChannelName=malformed_name,
            ClusterArn=malformed_cluster_arn,
            TopicConfigurationList=topic_config,
            S3DestinationConfiguration=destination,
        )

    malformed_code, malformed_msg = _refusal(ctx, kafka, malformed_cluster_arn, _malformed_call)
    assert malformed_code == "AccessDeniedException", (
        f"expected AccessDeniedException for a malformed ClusterArn, got={malformed_code}"
    )
    assert malformed_msg == (
        f"User: {identity['Arn']} is not authorized to perform: kafka:CreateChannel on resource: *"
    ), malformed_msg

    # Positive control: syntactically valid ARN shape, but the cluster does not exist --
    # authorization succeeds and it fails for the *different* reason (resource not found).
    valid_name = ctx.unique_name("sim2real-ch-")

    def _valid_call():
        return kafka.create_channel(
            ChannelName=valid_name,
            ClusterArn=bogus_cluster_arn,
            TopicConfigurationList=topic_config,
            S3DestinationConfiguration=destination,
        )

    valid_code, valid_msg = _refusal(ctx, kafka, bogus_cluster_arn, _valid_call)
    assert valid_code == "NotFoundException", (
        f"expected NotFoundException once the ClusterArn is syntactically valid, got {valid_code!r}"
    )
    assert valid_msg == _NOT_FOUND_MESSAGE, valid_msg


def _refusal(ctx, kafka, cluster_arn, fn):
    """Call fn(); return (Error.Code, Error.Message) of the ClientError it raises. An
    unexpected SUCCESS registers the channel's deletion and raises."""
    try:
        resp = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    arn = resp.get("ChannelArn")
    if arn:
        ctx.on_cleanup(lambda: kafka.delete_channel(ChannelArn=arn, ClusterArn=cluster_arn))
    raise AssertionError(f"expected CreateChannel to be refused, but it SUCCEEDED and returned {resp!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
