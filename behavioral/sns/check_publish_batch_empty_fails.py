"""publish-batch-empty-fails."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "publish-batch-empty-fails"
GROUP = 'publish'
SERVICES = ['sns']


def _error(fn):
    """Call fn(); return botocore (Error.Code, Error.Message) if a ClientError was raised. An unexpected
    SUCCESS raises, because an emulator ACCEPTING input real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except ClientError as exc:
        error = exc.response.get("Error", {})
        return error.get("Code"), error.get("Message")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


def _tags_kv():
    return [{"Key": "sim2real", "Value": CHECK}, {"Key": "sim2real:managed", "Value": "true"}]


def _create_topic(ctx, name=None):
    """Create a topic, register its teardown, and return its ARN."""
    sns = ctx.client("sns")
    name = name or ctx.unique_name("sim2real-behav-sns-topic-")
    arn = sns.create_topic(Name=name, Tags=_tags_kv())["TopicArn"]
    ctx.on_cleanup(lambda: sns.delete_topic(TopicArn=arn))
    return arn


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """[overly-permissive] PublishBatch with an empty entry list must be rejected, and the same
    topic must still accept a normal batch -- otherwise "rejects empty" is indistinguishable from
    "rejects every PublishBatch"."""
    sns = ctx.client("sns")
    arn = _create_topic(ctx)
    code, message = _error(
        lambda: sns.publish_batch(TopicArn=arn, PublishBatchRequestEntries=[])
    )
    assert code == "EmptyBatchRequest", f"got {code!r}"
    assert message == "The batch request doesn't contain any entries.", f"got {message!r}"

    # Positive control: the same topic and operation accept a real entry.
    resp = sns.publish_batch(
        TopicArn=arn,
        PublishBatchRequestEntries=[{"Id": "e0", "Message": "positive-control"}],
    )
    assert len(resp.get("Successful", [])) == 1 and not resp.get("Failed"), (
        f"expected the positive-control entry to succeed, got {resp!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
