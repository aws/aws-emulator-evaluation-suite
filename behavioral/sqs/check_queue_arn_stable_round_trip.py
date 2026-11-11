"""queue-arn-stable-round-trip."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "queue-arn-stable-round-trip"
GROUP = "invariants"
SERVICES = ["sqs"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """QueueArn returned by GetQueueAttributes matches the arn:aws:sqs:<region>:<account>:<name>
    format, is stable across repeated calls, and the queue name embedded in it matches both
    the URL from create_queue and the URL returned by GetQueueUrl."""
    sqs = ctx.client("sqs")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]
    name = ctx.unique_name("sim2real-behav-arn-")
    create_url = sqs.create_queue(
        QueueName=name,
        tags={"sim2real:managed": "true", "sim2real": "queue-arn-stable-round-trip"},
    )["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=create_url))

    lookup_url = sqs.get_queue_url(QueueName=name)["QueueUrl"]
    assert lookup_url == create_url, f"{lookup_url!r} != {create_url!r}"

    arn_first = sqs.get_queue_attributes(QueueUrl=create_url, AttributeNames=["QueueArn"])[
        "Attributes"
    ]["QueueArn"]
    arn_second = sqs.get_queue_attributes(QueueUrl=create_url, AttributeNames=["QueueArn"])[
        "Attributes"
    ]["QueueArn"]
    assert arn_first == arn_second, "QueueArn is not stable across repeated calls"

    expected_arn = f"arn:aws:sqs:{ctx.region}:{account_id}:{name}"
    assert arn_first == expected_arn, f"expected QueueArn {expected_arn!r}, got {arn_first!r}"

    name_segment = arn_first.split(":")[-1]
    assert name_segment == name, f"QueueArn name segment {name_segment!r} != {name!r}"

    url_segment = create_url.rstrip("/").split("/")[-1]
    assert url_segment == name, f"QueueUrl name segment {url_segment!r} != {name!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
