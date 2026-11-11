"""add-remove-permission."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "add-remove-permission"
GROUP = 'state'
SERVICES = ['sqs']


def _poll(fn, pred, *, timeout_s, interval_s):
    deadline = time.monotonic() + timeout_s
    val = fn()
    while not pred(val):
        if time.monotonic() >= deadline:
            return val
        time.sleep(interval_s)
        val = fn()
    return val


def _policy(sqs, url):
    # A queue with no policy set omits the "Attributes" key entirely.
    return sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["Policy"]).get("Attributes", {}).get("Policy")


def _sids(policy_json):
    return {stmt.get("Sid") for stmt in json.loads(policy_json)["Statement"]} if policy_json else set()


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """AddPermission inserts a policy statement identified by Label; RemovePermission removes it by Label."""
    sqs = ctx.client("sqs")
    url = sqs.create_queue(QueueName=ctx.unique_name("sim2real-behav-"))["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))

    arn = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]
    account = arn.split(":")[4]
    # SQS documents that an attribute change can take up to 60s to propagate, so the read is
    # eventually consistent with the write and must be polled rather than read once.
    timeout_s = 30

    sqs.add_permission(QueueUrl=url, Label="TestLabel1", AWSAccountIds=[account], Actions=["SendMessage"])
    policy = _poll(
        lambda: _policy(sqs, url),
        lambda p: "TestLabel1" in _sids(p),
        timeout_s=timeout_s,
        interval_s=2,
    )
    sids = _sids(policy)
    assert "TestLabel1" in sids, f"policy statement Sid TestLabel1 missing after AddPermission: {sids}"

    sqs.remove_permission(QueueUrl=url, Label="TestLabel1")
    removed = _poll(
        lambda: _policy(sqs, url),
        lambda p: "TestLabel1" not in _sids(p),
        timeout_s=timeout_s,
        interval_s=2,
    )
    removed_sids = _sids(removed)
    assert "TestLabel1" not in removed_sids, f"Sid TestLabel1 still present after RemovePermission: {removed_sids}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
