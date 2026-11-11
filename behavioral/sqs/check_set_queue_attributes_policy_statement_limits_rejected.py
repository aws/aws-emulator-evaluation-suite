"""set-queue-attributes-policy-statement-limits-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "set-queue-attributes-policy-statement-limits-rejected"
GROUP = "validation"
SERVICES = ["sqs"]

_PRINCIPAL_PROPAGATION_S = 180


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """SetQueueAttributes rejects a Policy document over 8,192 bytes, a statement with more than
    10 conditions, more than 7 actions, or more than 50 principals, each with its exact message
    and nothing stored; a document one under each bound persists.

    Reference: https://docs.aws.amazon.com/AWSSimpleQueueService/latest/SQSDeveloperGuide/sqs-basic-architecture.html
    """
    sqs = ctx.client("sqs")
    iam = ctx.client("iam")
    account_id = ctx.account

    url = sqs.create_queue(
        QueueName=ctx.unique_name("sim2real-behav-polstmt-"),
        tags={"sim2real-check": CHECK},
    )["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))
    arn = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]

    _check_size_limit(sqs, url, arn, account_id)
    _check_condition_limit(sqs, url, arn, account_id)
    _check_action_limit(sqs, url, arn, account_id)
    _check_principal_limit(ctx, sqs, iam, url, arn)


def _check_size_limit(sqs, url: str, arn: str, account_id: str) -> None:
    """A Policy document whose serialized size exceeds 8,192 bytes is refused; a small one with
    the identical shape persists."""
    oversized = _policy_with_condition(arn, account_id, {"aws:SourceAccount": "x" * 7900})
    assert len(json.dumps(oversized)) > 8192, "the oversized probe must itself exceed the bound"
    code, message = _error(lambda: sqs.set_queue_attributes(
        QueueUrl=url, Attributes={"Policy": json.dumps(oversized)}))
    assert code == "OverLimit", f"oversized Policy: expected OverLimit, got {code!r}"
    assert message == "Submitted policy is over max allowed size.", (
        f"oversized Policy: unexpected message {message!r}"
    )
    _assert_no_policy(sqs, url, "oversized Policy")

    small = _policy_with_condition(arn, account_id, {"aws:SourceAccount": "x" * 10})
    sqs.set_queue_attributes(QueueUrl=url, Attributes={"Policy": json.dumps(small)})
    stored = _get_policy(sqs, url)
    assert stored == small, f"a well-under-size Policy did not persist verbatim: {stored!r}"
    sqs.set_queue_attributes(QueueUrl=url, Attributes={"Policy": ""})


def _check_condition_limit(sqs, url: str, arn: str, account_id: str) -> None:
    """A statement with 11 conditions is refused; the same statement with 10 persists."""
    conditions11 = {"StringEquals": {f"aws:PrincipalTag/sim2real{i}": f"v{i}" for i in range(11)}}
    code, message = _error(lambda: sqs.set_queue_attributes(
        QueueUrl=url, Attributes={"Policy": json.dumps(
            _policy_with_condition(arn, account_id, None, conditions11))}))
    assert code == "OverLimit", f"11 conditions: expected OverLimit, got {code!r}"
    assert message == (
        "11 conditions were found in a statement from the submitted policy, max allowed is 10"
    ), f"11 conditions: unexpected message {message!r}"
    _assert_no_policy(sqs, url, "11-condition Policy")

    conditions10 = {"StringEquals": {f"aws:PrincipalTag/sim2real{i}": f"v{i}" for i in range(10)}}
    policy10 = _policy_with_condition(arn, account_id, None, conditions10)
    sqs.set_queue_attributes(QueueUrl=url, Attributes={"Policy": json.dumps(policy10)})
    stored = _get_policy(sqs, url)
    assert stored == policy10, f"a 10-condition Policy did not persist verbatim: {stored!r}"
    sqs.set_queue_attributes(QueueUrl=url, Attributes={"Policy": ""})


def _check_action_limit(sqs, url: str, arn: str, account_id: str) -> None:
    """A statement naming 8 actions is refused; the same statement with 7 persists."""
    all_actions = [
        "SQS:SendMessage", "SQS:ReceiveMessage", "SQS:DeleteMessage", "SQS:GetQueueAttributes",
        "SQS:GetQueueUrl", "SQS:ChangeMessageVisibility", "SQS:PurgeQueue", "SQS:SetQueueAttributes",
    ]
    code, message = _error(lambda: sqs.set_queue_attributes(
        QueueUrl=url, Attributes={"Policy": json.dumps(
            _policy_with_actions(arn, account_id, all_actions))}))
    assert code == "OverLimit", f"8 actions: expected OverLimit, got {code!r}"
    assert message == (
        "8 actions were found in a statement from the submitted policy, max allowed is 7"
    ), f"8 actions: unexpected message {message!r}"
    _assert_no_policy(sqs, url, "8-action Policy")

    policy7 = _policy_with_actions(arn, account_id, all_actions[:7])
    sqs.set_queue_attributes(QueueUrl=url, Attributes={"Policy": json.dumps(policy7)})
    stored = _get_policy(sqs, url)
    assert stored == policy7, f"a 7-action Policy did not persist verbatim: {stored!r}"
    sqs.set_queue_attributes(QueueUrl=url, Attributes={"Policy": ""})


def _check_principal_limit(ctx, sqs, iam, url: str, arn: str) -> None:
    """A statement naming 50 distinct IAM users persists; the same statement naming 51 is refused.

    SQS refuses a principal it cannot resolve yet with a generic message, so the 50-user policy and
    a policy naming the 51st user are retried until accepted before the 51-user refusal is sent.
    """
    users = []
    for i in range(51):
        name = ctx.unique_name(f"sim2real-behav-polprincipal-{i}-")
        user_arn = iam.create_user(UserName=name, Tags=[{"Key": "sim2real", "Value": CHECK}])["User"]["Arn"]
        ctx.on_cleanup(_teardown(lambda n=name: iam.delete_user(UserName=n), "NoSuchEntity"))
        users.append(user_arn)

    policy50 = _policy_with_principals(arn, users[:50])
    _set_policy_once_principals_resolve(ctx, sqs, url, policy50)
    stored = _get_policy(sqs, url)
    stored_principals = stored["Statement"][0]["Principal"]["AWS"] if stored else None
    assert stored and sorted(stored_principals) == sorted(users[:50]), (
        f"a 50-principal Policy did not persist the same principal set: {stored_principals!r}"
    )
    sqs.set_queue_attributes(QueueUrl=url, Attributes={"Policy": ""})

    _set_policy_once_principals_resolve(ctx, sqs, url, _policy_with_principals(arn, users[50:]))
    sqs.set_queue_attributes(QueueUrl=url, Attributes={"Policy": ""})

    code, message = _error(lambda: sqs.set_queue_attributes(
        QueueUrl=url, Attributes={"Policy": json.dumps(_policy_with_principals(arn, users))}))
    assert code == "InvalidAttributeValue", f"51 principals: expected InvalidAttributeValue, got {code!r}"
    assert message == (
        "Invalid value for the parameter 51 principals were found in a statement from the "
        "submitted policy, max allowed is 50."
    ), f"51 principals: unexpected message {message!r}"
    _assert_no_policy(sqs, url, "51-principal Policy")


def _set_policy_once_principals_resolve(ctx, sqs, url: str, policy: dict) -> None:
    """SetQueueAttributes(Policy), retried only while SQS cannot yet resolve a new IAM principal."""
    timeout_s = _budget_s(ctx, _PRINCIPAL_PROPAGATION_S)
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            sqs.set_queue_attributes(QueueUrl=url, Attributes={"Policy": json.dumps(policy)})
            return
        except ClientError as exc:
            err = exc.response["Error"]
            if err.get("Message") != "Invalid value for the parameter Policy.":
                raise
            if time.monotonic() >= deadline:
                raise TimeoutError(
                    f"SQS still refused the new IAM users as principals after {timeout_s:.0f}s: "
                    f"{err!r}"
                ) from exc
            time.sleep(2)


def _budget_s(ctx, cap_s):
    """A wait's timeout, bounded by the runner's remaining time so the wait fails with its own message."""
    left = ctx.time_left()
    return max(1.0, min(cap_s, (cap_s if left is None else left) - 5.0))


def _policy_with_condition(arn: str, account_id: str, condition: dict | None,
                           conditions: dict | None = None) -> dict:
    # A bare account-id Principal reads back normalized to its root ARN; writing the root ARN
    # directly keeps the round-trip assertion about this check's own claim, not that normalization.
    stmt = {"Sid": "SimReal", "Effect": "Allow",
            "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"},
            "Action": "SQS:SendMessage", "Resource": arn}
    if condition is not None:
        stmt["Condition"] = {"StringEquals": condition}
    elif conditions is not None:
        stmt["Condition"] = conditions
    return {"Version": "2012-10-17", "Statement": [stmt]}


def _policy_with_actions(arn: str, account_id: str, actions: list) -> dict:
    stmt = {"Sid": "SimReal", "Effect": "Allow",
            "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"},
            "Action": actions, "Resource": arn}
    return {"Version": "2012-10-17", "Statement": [stmt]}


def _policy_with_principals(arn: str, principals: list) -> dict:
    stmt = {"Sid": "SimReal", "Effect": "Allow", "Principal": {"AWS": principals},
            "Action": "SQS:SendMessage", "Resource": arn}
    return {"Version": "2012-10-17", "Statement": [stmt]}


def _get_policy(sqs, url: str) -> dict | None:
    raw = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["Policy"]).get(
        "Attributes", {}).get("Policy")
    return None if raw is None else json.loads(raw)


def _assert_no_policy(sqs, url: str, label: str) -> None:
    stored = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["Policy"]).get(
        "Attributes", {}).get("Policy")
    assert stored is None, f"{label} was refused but a Policy is still stored: {stored!r}"


def _error(fn) -> tuple[str, str]:
    """The (Code, Message) of the ClientError ``fn`` raises. An unexpected success raises too."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


def _teardown(undo, *not_found: str):
    """A cleanup running ``undo()`` where a failed delete raises."""

    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
