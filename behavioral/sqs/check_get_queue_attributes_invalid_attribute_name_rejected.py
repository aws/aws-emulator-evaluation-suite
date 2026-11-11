"""get-queue-attributes-invalid-attribute-name-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-queue-attributes-invalid-attribute-name-rejected"
GROUP = "overly-permissive"
SERVICES = ["sqs"]

# Exact messages real SQS returns for these refusals.
MSG_BAD_ATTR = 'Unknown Attribute NotARealAttributeName.'


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """GetQueueAttributes rejects an unrecognized AttributeName; a valid name in the same call set still works."""
    sqs = ctx.client("sqs")
    url = sqs.create_queue(
        QueueName=ctx.unique_name("sim2real-behav-"), tags={"sim2real": CHECK}
    )["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))

    # Positive control: a valid attribute name on this queue succeeds and returns real data.
    attrs = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])["Attributes"]
    assert attrs["QueueArn"].startswith("arn:aws:sqs:"), (
        f"positive control failed: QueueArn was {attrs.get('QueueArn')!r}"
    )

    err = _client_error(
        lambda: sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["NotARealAttributeName"])
    )
    assert err.get("Code") == "InvalidAttributeName", (
        f"expected InvalidAttributeName for an unrecognized AttributeName, got {err!r}"
    )
    assert err.get("Message") == MSG_BAD_ATTR, f"got {err!r}"


def _client_error(fn):
    """Call fn(); return its botocore Error dict. An unexpected SUCCESS raises, because an emulator
    ACCEPTING input real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {})
    raise AssertionError(
        f"real AWS rejects GetQueueAttributes(AttributeNames=['NotARealAttributeName']), but it "
        f"SUCCEEDED and returned {result!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
