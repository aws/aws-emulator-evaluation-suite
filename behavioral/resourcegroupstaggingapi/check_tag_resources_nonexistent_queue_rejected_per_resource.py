"""tag-resources-nonexistent-queue-rejected-per-resource."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "tag-resources-nonexistent-queue-rejected-per-resource"
GROUP = "overly-permissive"
SERVICES = ["resourcegroupstaggingapi"]


@tags("axis:rejection", "cap:c2", "concern:negative-classes", "concern:data-plane",
      "dp:api", "plane:data")
def run(ctx) -> None:
    """A TagResources batch naming one live and one absent queue succeeds, tags the live one and
    lists the absent one in FailedResourcesMap with SQS's own
    AWS.SimpleQueueService.NonExistentQueue code; the absent ARN never enters the index.
    """
    sqs = ctx.client("sqs")
    rgt = ctx.client("resourcegroupstaggingapi")
    sts = ctx.client("sts")

    account = sts.get_caller_identity()["Account"]
    key = ctx.unique_name("sim2real-behav-part-")

    q_url = sqs.create_queue(QueueName=ctx.unique_name("sim2real-behav-q-"))["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=q_url))
    live_arn = sqs.get_queue_attributes(QueueUrl=q_url, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]

    # A syntactically valid ARN for a queue this check never creates, in this account and region so
    # only the queue's existence is wrong.
    ghost_arn = f"arn:aws:sqs:{ctx.region}:{account}:{ctx.unique_name('sim2real-behav-ghost-')}"

    result = rgt.tag_resources(ResourceARNList=[live_arn, ghost_arn], Tags={key: "partial"})
    ctx.on_cleanup(lambda: rgt.untag_resources(ResourceARNList=[live_arn], TagKeys=[key]))

    failed = result["FailedResourcesMap"]
    assert set(failed) == {ghost_arn}, (
        f"FailedResourcesMap named {sorted(failed)!r}, expected exactly the absent queue "
        f"{ghost_arn!r} — the live queue {live_arn!r} must not fail and the absent one must not pass"
    )
    detail = failed[ghost_arn]
    assert detail["ErrorCode"] == "AWS.SimpleQueueService.NonExistentQueue", (
        f"the per-resource ErrorCode for an absent queue was {detail['ErrorCode']!r}, expected "
        f"SQS's own AWS.SimpleQueueService.NonExistentQueue"
    )
    assert detail["StatusCode"] == 400, (
        f"the per-resource StatusCode was {detail['StatusCode']!r}, expected 400"
    )
    expected = "The specified queue does not exist."
    assert detail["ErrorMessage"] == expected, (
        f"the per-resource ErrorMessage for an absent queue was {detail['ErrorMessage']!r}, "
        f"expected {expected!r}"
    )

    # Positive control, in the same call: the good ARN really was tagged.
    settled = _poll_until(
        lambda: {m["ResourceARN"] for m in _all_resources(rgt, TagFilters=[{"Key": key}])},
        lambda arns: arns == {live_arn},
        timeout_s=180.0,
    )
    assert live_arn in settled, (
        f"the live queue {live_arn!r} never reached the index under {key!r} (saw {sorted(settled)!r}) "
        f"— a partial failure must still apply the tags that succeeded"
    )

    # Effect absent: the absent ARN was not indexed anyway.
    assert ghost_arn not in settled, (
        f"the absent queue {ghost_arn!r} was indexed under {key!r} despite being reported as failed"
    )
    assert settled == {live_arn}, (
        f"tag filter {key!r} matched {sorted(settled)!r}, expected exactly the live queue"
    )


def _all_resources(rgt, **kwargs):
    """Every ResourceTagMapping for a GetResources query, following PaginationToken to the end."""
    out, token = [], ""
    while True:
        page = rgt.get_resources(**kwargs, **({"PaginationToken": token} if token else {}))
        out.extend(page["ResourceTagMappingList"])
        token = page["PaginationToken"]
        if not token:
            return out


def _poll_until(probe, predicate, timeout_s=180.0, interval_s=3.0):
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
