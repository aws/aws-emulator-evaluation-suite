"""queue-arn-and-get-queue-url-consistency."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "queue-arn-and-get-queue-url-consistency"
GROUP = "metadata"
SERVICES = ["sqs"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """QueueArn embeds the correct region/account/name, and GetQueueUrl resolves back to the CreateQueue URL."""
    sqs = ctx.client("sqs")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]

    name = ctx.unique_name("sim2real-behav-")
    created_url = sqs.create_queue(QueueName=name, tags={"sim2real:managed": "true"})["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=created_url))

    arn = sqs.get_queue_attributes(QueueUrl=created_url, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]
    parts = arn.split(":")
    assert parts[0] == "arn", f"QueueArn {arn!r} does not start with 'arn': {parts[0]!r}"
    assert parts[2] == "sqs", f"QueueArn {arn!r} service segment is not 'sqs': {parts[2]!r}"
    assert parts[3] == ctx.region, f"QueueArn {arn!r} region segment {parts[3]!r} != {ctx.region!r}"
    assert parts[4] == account_id, f"QueueArn {arn!r} account segment {parts[4]!r} != {account_id!r}"
    assert parts[5] == name, f"QueueArn {arn!r} name segment {parts[5]!r} != {name!r}"

    resolved_url = sqs.get_queue_url(QueueName=name)["QueueUrl"]
    assert resolved_url == created_url, (
        f"GetQueueUrl resolved {resolved_url!r}, expected the CreateQueue URL {created_url!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
