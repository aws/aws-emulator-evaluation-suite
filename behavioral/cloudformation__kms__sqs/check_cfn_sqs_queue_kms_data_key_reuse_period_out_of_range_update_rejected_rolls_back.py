"""cfn-sqs-queue-kms-data-key-reuse-period-out-of-range-update-rejected-rolls-back."""
from __future__ import annotations

import re
import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cfn-sqs-queue-kms-data-key-reuse-period-out-of-range-update-rejected-rolls-back"
GROUP = "deploy-cfn-sqs-kms"
SERVICES = ["cloudformation", "kms", "sqs"]

_TEMPLATE = """\
AWSTemplateFormatVersion: '2010-09-09'
Parameters:
  QueueName:
    Type: String
  KmsKeyId:
    Type: String
  ReusePeriod:
    Type: Number
Resources:
  Queue:
    Type: AWS::SQS::Queue
    Properties:
      QueueName: !Ref QueueName
      KmsMasterKeyId: !Ref KmsKeyId
      KmsDataKeyReusePeriodSeconds: !Ref ReusePeriod
Outputs:
  QueueUrl:
    Value: !Ref Queue
"""

_STACK_TERMINAL = {
    "CREATE_COMPLETE", "CREATE_FAILED", "ROLLBACK_COMPLETE", "ROLLBACK_FAILED",
    "UPDATE_COMPLETE", "UPDATE_FAILED", "UPDATE_ROLLBACK_COMPLETE",
    "UPDATE_ROLLBACK_FAILED", "DELETE_COMPLETE", "DELETE_FAILED",
}

_GOOD_PERIOD = 300

_HANDLER_REASON = re.compile(
    r'^Resource handler returned message: "(?P<message>.*)" '
    r"\(RequestToken: [0-9a-f-]+, HandlerErrorCode: (?P<code>[A-Za-z]+)\)$",
    re.DOTALL,
)
_REJECTED = (
    "Invalid value for the parameter KmsDataKeyReusePeriodSeconds. (Service: Sqs, Status "
    "Code: 400, Request ID: <id>) (SDK Attempt Count: <n>)",
    "InvalidRequest",
)


def _handler_reason(reason: str) -> tuple[str, str]:
    """``(masked message, HandlerErrorCode)`` of a registry-handler failure reason.

    Masks only the per-call Request ID and SDK attempt count; everything else compares with ==.
    """
    m = _HANDLER_REASON.match(reason or "")
    assert m is not None, f"not a resource-handler failure reason: {reason!r}"
    message = re.sub(r"Request ID: [0-9a-f-]+", "Request ID: <id>", m["message"])
    message = re.sub(r"SDK Attempt Count: \d+", "SDK Attempt Count: <n>", message)
    return message, m["code"]


@tags(
    "axis:rejection", "cap:c1", "concern:deploy", "concern:negative-classes",
    "concern:representation", "dp:api", "plane:data",
)
def run(ctx) -> None:
    """A stack update that sets KmsDataKeyReusePeriodSeconds below the documented 60-second
    floor rolls the stack back, and the queue keeps its last-good reuse period and stays usable.
    """
    cfn = ctx.client("cloudformation")
    sqs = ctx.client("sqs")
    kms = ctx.client("kms")

    key = _create_key(ctx, kms)
    stack = ctx.unique_name("sim2real-behav-cfn-ssekmsrej-")
    queue_name = ctx.unique_name("sim2real-behav-ssekmsrej-q-")
    ctx.on_cleanup(lambda: _delete_stack_and_wait(cfn, stack))

    # ---- positive control: a valid reuse period deploys and the queue works ---------------
    cfn.create_stack(
        StackName=stack,
        TemplateBody=_TEMPLATE,
        Tags=[{"Key": "sim2real", "Value": CHECK}],
        Parameters=_params(queue_name, key["KeyId"], _GOOD_PERIOD),
    )
    created = _wait_terminal(cfn, stack)
    assert created["StackStatus"] == "CREATE_COMPLETE", (
        f"initial create reached {created['StackStatus']!r}: {created.get('StackStatusReason')!r}"
    )
    outputs = {o["OutputKey"]: o["OutputValue"] for o in created.get("Outputs", [])}
    queue_url = outputs["QueueUrl"]
    attrs = _get_attrs(sqs, queue_url)
    assert attrs["KmsDataKeyReusePeriodSeconds"] == str(_GOOD_PERIOD), (
        f"KmsDataKeyReusePeriodSeconds after create is "
        f"{attrs.get('KmsDataKeyReusePeriodSeconds')!r}, expected {str(_GOOD_PERIOD)!r}"
    )
    _round_trip(sqs, queue_url, "before-the-rejected-update")

    # ---- break exactly one thing: a reuse period below the 60-second floor ---------------
    cfn.update_stack(
        StackName=stack, TemplateBody=_TEMPLATE,
        Parameters=_params(queue_name, key["KeyId"], 59),
    )
    failed = _wait_terminal(cfn, stack)
    assert failed["StackStatus"] == "UPDATE_ROLLBACK_COMPLETE", (
        f"an out-of-range KmsDataKeyReusePeriodSeconds update reached "
        f"{failed['StackStatus']!r}, expected UPDATE_ROLLBACK_COMPLETE"
    )
    raw_reason = _resource_failure_reason(cfn, stack, "Queue")
    got = _handler_reason(raw_reason)
    assert got == _REJECTED, f"the queue resource's failure reason is {got!r}, expected {_REJECTED!r}"

    # ---- the effect is absent: GetQueueAttributes still reports the last-good period ------
    attrs = _get_attrs(sqs, queue_url)
    assert attrs["KmsDataKeyReusePeriodSeconds"] == str(_GOOD_PERIOD), (
        f"after the rolled-back update, KmsDataKeyReusePeriodSeconds is "
        f"{attrs.get('KmsDataKeyReusePeriodSeconds')!r}, expected the surviving "
        f"{str(_GOOD_PERIOD)!r} — the rejected value must never have taken effect"
    )

    # ---- restore: the identical call that failed now succeeds once the value is valid -----
    cfn.update_stack(
        StackName=stack, TemplateBody=_TEMPLATE,
        Parameters=_params(queue_name, key["KeyId"], 120),
    )
    restored = _wait_terminal(cfn, stack)
    assert restored["StackStatus"] == "UPDATE_COMPLETE", (
        f"a valid reuse period update reached {restored['StackStatus']!r} after the rejected "
        f"one, expected UPDATE_COMPLETE"
    )
    attrs = _get_attrs(sqs, queue_url)
    assert attrs["KmsDataKeyReusePeriodSeconds"] == "120", (
        f"KmsDataKeyReusePeriodSeconds after the valid update is "
        f"{attrs.get('KmsDataKeyReusePeriodSeconds')!r}, expected '120'"
    )
    _round_trip(sqs, queue_url, "after-the-restoring-update")


def _params(queue_name: str, key_id: str, reuse_period: int) -> list[dict[str, str]]:
    return [
        {"ParameterKey": "QueueName", "ParameterValue": queue_name},
        {"ParameterKey": "KmsKeyId", "ParameterValue": key_id},
        {"ParameterKey": "ReusePeriod", "ParameterValue": str(reuse_period)},
    ]


def _create_key(ctx, kms) -> dict[str, str]:
    """A customer-managed key under the default (root-trust) key policy, torn down to
    PendingDeletion with its alias removed outright."""
    created = kms.create_key(
        Description="sim2real behavioral key",
        Tags=[{"TagKey": "sim2real", "TagValue": CHECK}],
    )["KeyMetadata"]
    key_id = created["KeyId"]
    ctx.on_cleanup(lambda: kms.schedule_key_deletion(KeyId=key_id, PendingWindowInDays=7))
    alias = ctx.unique_name("alias/sim2real-behav-ssekmsrej-")
    kms.create_alias(AliasName=alias, TargetKeyId=key_id)
    ctx.on_cleanup(lambda: kms.delete_alias(AliasName=alias))
    return {"KeyId": key_id, "Arn": created["Arn"]}


def _get_attrs(sqs, queue_url: str) -> dict[str, str]:
    return sqs.get_queue_attributes(QueueUrl=queue_url, AttributeNames=["All"])["Attributes"]


def _round_trip(sqs, queue_url: str, body: str) -> None:
    sent = sqs.send_message(QueueUrl=queue_url, MessageBody=body)["MessageId"]
    got = _poll_until(
        lambda: sqs.receive_message(
            QueueUrl=queue_url, MaxNumberOfMessages=1, WaitTimeSeconds=5
        ).get("Messages", []),
        lambda ms: bool(ms), timeout_s=60.0, interval_s=2.0,
        description=f"a message on {queue_url!r}",
    )
    assert got[0]["MessageId"] == sent, (
        f"received message id {got[0]['MessageId']!r}, expected the sent {sent!r}"
    )
    sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=got[0]["ReceiptHandle"])


def _resource_failure_reason(cfn, stack: str, logical_id: str) -> str:
    """The StatusReason of ``logical_id``'s own UPDATE_FAILED event in this stack's latest
    rollback, independent of the stack-level StackStatusReason."""
    for page in cfn.get_paginator("describe_stack_events").paginate(StackName=stack):
        for event in page["StackEvents"]:
            if (event["LogicalResourceId"] == logical_id
                    and event["ResourceStatus"] == "UPDATE_FAILED"):
                return event["ResourceStatusReason"]
    raise AssertionError(f"no UPDATE_FAILED event for resource {logical_id!r} in stack {stack!r}")


def _poll_until(probe, predicate, *, timeout_s: float, interval_s: float, description: str):
    deadline = time.monotonic() + timeout_s
    last: Any = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s; last saw {last!r}")


def _describe(cfn, stack):
    try:
        return cfn.describe_stacks(StackName=stack)["Stacks"][0]
    except ClientError:
        return None


def _wait_terminal(cfn, stack, *, timeout_s: float = 900.0, interval_s: float = 5.0):
    return _poll_until(
        lambda: _describe(cfn, stack),
        lambda s: s is not None and s["StackStatus"] in _STACK_TERMINAL,
        timeout_s=timeout_s, interval_s=interval_s,
        description=f"stack {stack!r} reaching a terminal status",
    )


def _delete_stack_and_wait(cfn, stack: str) -> None:
    if _describe(cfn, stack) is None:
        return
    cfn.delete_stack(StackName=stack)
    deadline = time.monotonic() + 900.0
    last = "never read"
    while time.monotonic() < deadline:
        s = _describe(cfn, stack)
        if s is None:
            return
        last = s["StackStatus"]
        if last == "DELETE_COMPLETE":
            return
        if last == "DELETE_FAILED":
            raise AssertionError(f"stack {stack!r} is DELETE_FAILED: {s.get('StackStatusReason')!r}")
        time.sleep(5.0)
    raise AssertionError(f"stack {stack!r} did not reach DELETE_COMPLETE within 900s (last={last!r})")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
