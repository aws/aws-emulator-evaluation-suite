"""channel-duplicate-name-conflict."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "channel-duplicate-name-conflict"
GROUP = 'overly-permissive'
SERVICES = ['kafka']

_NOT_FOUND = ("NotFoundException", "The requested resource doesn\u2019t exist.")

def _err(fn):
    """Call fn(); return (Error.Code, Error.Message) of the ClientError it raises. An unexpected
    SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        error = exc.response.get("Error", {})
        return error.get("Code"), error.get("Message")
    raise AssertionError(f"expected the call to be refused, but it SUCCEEDED and returned {result!r}")


def _account_id(ctx):
    if not hasattr(ctx, "_kafka_account_id"):
        ctx._kafka_account_id = ctx.client("sts").get_caller_identity()["Account"]
    return ctx._kafka_account_id


def _bogus_cluster_arn(ctx):
    """A well-formed MSK cluster ARN, in this account, that cannot exist."""
    return (
        f"arn:aws:kafka:{ctx.region}:{_account_id(ctx)}:cluster/"
        f"{ctx.unique_name('sim2real-behav-nonexistent-')}/"
        "00000000-0000-0000-0000-000000000000-1"
    )


def _bogus_channel_arn(ctx):
    return (
        f"arn:aws:kafka:{ctx.region}:{_account_id(ctx)}:channel/"
        f"{ctx.unique_name('sim2real-behav-ghost-')}/"
        "00000000-0000-0000-0000-000000000000-5"
    )


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateChannel naming a cluster that does not exist fails with NotFoundException, the identical retry
    repeats it rather than a ConflictException, and ListChannels and DeleteChannel for that cluster fail
    with NotFoundException too."""
    msk = ctx.client("kafka")
    create_channel = getattr(msk, "create_channel", None)
    if create_channel is None:
        raise AssertionError("CreateChannel absent from the installed botocore model")

    cluster_arn = _bogus_cluster_arn(ctx)
    channel_name = ctx.unique_name("sim2real-behav-chan-")
    role_arn = f"arn:aws:iam::{_account_id(ctx)}:role/{ctx.unique_name('sim2real-behav-chrole-')}"

    def attempt():
        return create_channel(
            ChannelName=channel_name,
            ClusterArn=cluster_arn,
            TopicConfigurationList=[
                {
                    "TopicArn": (
                        f"arn:aws:kafka:{ctx.region}:{_account_id(ctx)}:topic/"
                        f"{ctx.unique_name('sim2real-behav-ghost-')}/"
                        "00000000-0000-0000-0000-000000000000-3/sim2real-behav-src-topic"
                    ),
                    "RecordConverter": {"ValueConverter": "JSON"},
                }
            ],
            S3DestinationConfiguration={
                "ServiceExecutionRoleArn": role_arn,
                "DataFreshnessInSeconds": 300,
                "DeadLetterQueueS3": {
                    "BucketArn": f"arn:aws:s3:::{ctx.unique_name('sim2real-behav-chdlq-')}",
                    "ErrorOutputPrefix": "dlq/",
                },
                "Storage": {
                    "BucketArn": f"arn:aws:s3:::{ctx.unique_name('sim2real-behav-chbkt-')}",
                    "StorageClass": "STANDARD",
                    "CompressionType": "GZIP",
                },
            },
        )

    first = _err(attempt)
    assert first == _NOT_FOUND, f"CreateChannel: expected NotFoundException, got {first}"
    retry = _err(attempt)
    assert retry == _NOT_FOUND, (
        f"a rejected CreateChannel must not reserve the name; retry got {retry}"
    )

    list_code = _err(lambda: msk.list_channels(ClusterArn=cluster_arn))
    assert list_code == _NOT_FOUND, f"ListChannels: expected NotFoundException, got {list_code}"

    delete_channel = getattr(msk, "delete_channel", None)
    if delete_channel is not None:
        del_code = _err(
            lambda: delete_channel(ChannelArn=_bogus_channel_arn(ctx), ClusterArn=cluster_arn)
        )
        assert del_code == _NOT_FOUND, f"DeleteChannel: expected NotFoundException, got {del_code}"

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
