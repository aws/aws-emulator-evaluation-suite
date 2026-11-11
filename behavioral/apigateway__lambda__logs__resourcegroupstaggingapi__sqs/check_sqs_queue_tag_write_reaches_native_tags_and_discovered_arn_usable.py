"""sqs-queue-tag-write-reaches-native-tags-and-discovered-arn-usable."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "sqs-queue-tag-write-reaches-native-tags-and-discovered-arn-usable"
GROUP = "tagging-discovery"
SERVICES = ["apigateway", "lambda", "logs", "resourcegroupstaggingapi", "sqs"]


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """Two tagged SQS queues are both found by GetResources; the discovered ARN resolves to a queue
    that round-trips a message, and TagResources/UntagResources on it reach (and withdraw from) the
    queue's native ListQueueTags without touching unrelated tags."""
    rgt = ctx.client("resourcegroupstaggingapi")
    sqs = ctx.client("sqs")

    run_tag = ctx.unique_name("sim2real-behav-run-")
    primary_name = ctx.unique_name("sim2real-behav-q1-")
    secondary_name = ctx.unique_name("sim2real-behav-q2-")

    primary_url = sqs.create_queue(
        QueueName=primary_name, tags={"Run": run_tag, "Team": "platform", "Env": "dev"},
    )["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=primary_url))
    primary_arn = sqs.get_queue_attributes(
        QueueUrl=primary_url, AttributeNames=["QueueArn"],
    )["Attributes"]["QueueArn"]

    secondary_url = sqs.create_queue(QueueName=secondary_name, tags={"Run": run_tag})["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=secondary_url))

    matched = _poll_until(
        lambda: rgt.get_resources(
            ResourceTypeFilters=["sqs:queue"], TagFilters=[{"Key": "Run", "Values": [run_tag]}],
        )["ResourceTagMappingList"],
        lambda mappings: {m["ResourceARN"] for m in mappings} == {primary_arn, _queue_arn(sqs, secondary_url)},
        timeout_s=120.0,
    )
    found_arns = {m["ResourceARN"] for m in matched}
    secondary_arn = _queue_arn(sqs, secondary_url)
    assert found_arns == {primary_arn, secondary_arn}, (
        f"GetResources matched {sorted(found_arns)!r}, expected exactly the two queues created"
    )
    primary_mapping = next(m for m in matched if m["ResourceARN"] == primary_arn)
    index_tags = {t["Key"]: t["Value"] for t in primary_mapping["Tags"]}
    assert index_tags == {"Run": run_tag, "Team": "platform", "Env": "dev"}, (
        f"tagging-api index reports {index_tags!r} for the primary queue, expected all three tags"
    )

    discovered_name = primary_arn.rsplit(":", 1)[1]
    discovered_url = sqs.get_queue_url(QueueName=discovered_name)["QueueUrl"]
    assert discovered_url == primary_url, (
        f"the name derived from the discovered ARN resolved to {discovered_url!r}, expected the "
        f"original {primary_url!r}"
    )
    body = ctx.unique_name("sim2real-behav-payload-")
    sqs.send_message(QueueUrl=discovered_url, MessageBody=body)
    received = sqs.receive_message(
        QueueUrl=discovered_url, WaitTimeSeconds=10, MaxNumberOfMessages=1,
    ).get("Messages", [])
    assert received and received[0]["Body"] == body, (
        f"sending through the ARN-derived queue URL did not deliver the payload; received "
        f"{received!r}"
    )
    sqs.delete_message(QueueUrl=discovered_url, ReceiptHandle=received[0]["ReceiptHandle"])

    tagged = rgt.tag_resources(ResourceARNList=[primary_arn], Tags={"Owner": "compat"})
    assert tagged["FailedResourcesMap"] == {}, (
        f"TagResources reported per-resource failures: {tagged['FailedResourcesMap']!r}"
    )
    native_after_tag = sqs.list_queue_tags(QueueUrl=primary_url)["Tags"]
    assert native_after_tag.get("Owner") == "compat", (
        f"SQS's own ListQueueTags reports {native_after_tag!r} after a TagResources call made "
        f"through the tagging API; Owner=compat did not reach the native tag store"
    )

    untagged = rgt.untag_resources(ResourceARNList=[primary_arn], TagKeys=["Owner"])
    assert untagged["FailedResourcesMap"] == {}, (
        f"UntagResources reported per-resource failures: {untagged['FailedResourcesMap']!r}"
    )
    native_after_untag = sqs.list_queue_tags(QueueUrl=primary_url)["Tags"]
    assert "Owner" not in native_after_untag, (
        f"SQS's own ListQueueTags still reports {native_after_untag!r} after an UntagResources "
        f"call made through the tagging API withdrew Owner"
    )
    assert native_after_untag.get("Env") == "dev", (
        f"UntagResources(Owner) also removed an unrelated tag: {native_after_untag!r}"
    )


def _queue_arn(sqs, url: str) -> str:
    return sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]


def _poll_until(probe, predicate, timeout_s=120.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    last = probe()
    while time.monotonic() < deadline:
        if predicate(last):
            return last
        time.sleep(interval_s)
        last = probe()
    return last


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
