"""remove-permission-nonexistent-label-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "remove-permission-nonexistent-label-rejected"
GROUP = "error-semantics"
SERVICES = ["sqs"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """RemovePermission for a Label that was never granted fails instead of succeeding as
    a no-op, leaves the existing policy statement intact, and removing the real label
    still works."""
    sqs = ctx.client("sqs")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]
    timeout_s = 30

    url = sqs.create_queue(QueueName=ctx.unique_name("sim2real-behav-rmperm-"))["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))

    existing_label = ctx.unique_name("ExistingLabel")
    sqs.add_permission(
        QueueUrl=url,
        Label=existing_label,
        AWSAccountIds=[account_id],
        Actions=["SendMessage"],
    )
    policy_after_add = _poll(
        lambda: _policy(sqs, url),
        lambda p: p is not None and existing_label in p,
        timeout_s=timeout_s,
    )
    assert policy_after_add is not None and existing_label in policy_after_add, (
        f"AddPermission statement for {existing_label!r} never appeared in policy: {policy_after_add!r}"
    )

    never_granted_label = ctx.unique_name("NeverGrantedLabel")
    code, message = _error(
        lambda: sqs.remove_permission(QueueUrl=url, Label=never_granted_label)
    )
    assert code == "InvalidParameterValue", (
        f"expected InvalidParameterValue removing a never-granted Label, got {code!r}"
    )
    assert message == (
        f"Value {never_granted_label} for parameter Label is invalid. "
        f"Reason: can't find label on existing policy."
    ), f"unexpected refusal message {message!r}"

    # effect absent: the real, existing statement is still present
    policy_after_reject = _policy(sqs, url)
    assert policy_after_reject is not None and existing_label in policy_after_reject, (
        f"rejected RemovePermission on {never_granted_label!r} disturbed the existing "
        f"statement for {existing_label!r}: {policy_after_reject!r}"
    )

    # positive control: removing the label that actually exists succeeds
    sqs.remove_permission(QueueUrl=url, Label=existing_label)
    policy_after_control = _poll(
        lambda: _policy(sqs, url),
        lambda p: p is None or existing_label not in p,
        timeout_s=timeout_s,
    )
    assert policy_after_control is None or existing_label not in policy_after_control, (
        f"label {existing_label!r} still present after RemovePermission: {policy_after_control!r}"
    )


def _policy(sqs, url):
    # A queue with no policy set omits the "Attributes" key entirely.
    return sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["Policy"]).get("Attributes", {}).get("Policy")


def _poll(fn, pred, *, timeout_s, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    val = fn()
    while not pred(val):
        if time.monotonic() >= deadline:
            return val
        time.sleep(interval_s)
        val = fn()
    return val


def _error(fn):
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(
        f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
