"""cfn-sqs-queue-kms-sse-properties-update-in-place-round-trip."""
from __future__ import annotations

import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cfn-sqs-queue-kms-sse-properties-update-in-place-round-trip"
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
  SqsManagedSse:
    Type: String
    AllowedValues: ['true', 'false']
Conditions:
  UseKms: !Equals [!Ref SqsManagedSse, 'false']
Resources:
  Queue:
    Type: AWS::SQS::Queue
    Properties:
      QueueName: !Ref QueueName
      KmsMasterKeyId: !If [UseKms, !Ref KmsKeyId, !Ref 'AWS::NoValue']
      KmsDataKeyReusePeriodSeconds: !If [UseKms, !Ref ReusePeriod, !Ref 'AWS::NoValue']
      SqsManagedSseEnabled: !If [UseKms, !Ref 'AWS::NoValue', !Ref SqsManagedSse]
Outputs:
  QueueUrl:
    Value: !Ref Queue
  QueueArn:
    Value: !GetAtt Queue.Arn
"""

_STACK_TERMINAL = {
    "CREATE_COMPLETE", "CREATE_FAILED", "ROLLBACK_COMPLETE", "ROLLBACK_FAILED",
    "UPDATE_COMPLETE", "UPDATE_FAILED", "UPDATE_ROLLBACK_COMPLETE",
    "UPDATE_ROLLBACK_FAILED", "DELETE_COMPLETE", "DELETE_FAILED",
}


@tags(
    "axis:happy-path", "cap:c1", "concern:data-plane", "concern:deploy",
    "concern:representation", "dp:api", "plane:data",
)
def run(ctx) -> None:
    """A deployed queue's KmsMasterKeyId and KmsDataKeyReusePeriodSeconds are the ones the
    template set; a stack update swaps the key and period in place with no new QueueUrl, and
    switching to SqsManagedSseEnabled removes KmsMasterKeyId. The queue works at every stage.
    """
    cfn = ctx.client("cloudformation")
    sqs = ctx.client("sqs")
    kms = ctx.client("kms")

    key1 = _create_key(ctx, kms, "one")
    key2 = _create_key(ctx, kms, "two")

    stack = ctx.unique_name("sim2real-behav-cfn-ssekms-")
    queue_name = ctx.unique_name("sim2real-behav-ssekms-q-")
    ctx.on_cleanup(lambda: _delete_stack_and_wait(cfn, stack))

    cfn.create_stack(
        StackName=stack,
        TemplateBody=_TEMPLATE,
        Tags=[{"Key": "sim2real", "Value": CHECK}],
        Parameters=_params(queue_name, key1["KeyId"], 70, "false"),
    )
    created = _wait_terminal(cfn, stack)
    assert created["StackStatus"] == "CREATE_COMPLETE", (
        f"initial create reached {created['StackStatus']!r}: {created.get('StackStatusReason')!r}"
    )
    outputs = {o["OutputKey"]: o["OutputValue"] for o in created.get("Outputs", [])}
    queue_url = outputs["QueueUrl"]
    queue_arn = outputs["QueueArn"]

    attrs = _get_attrs(sqs, queue_url)
    assert attrs["KmsMasterKeyId"] == key1["KeyId"], (
        f"KmsMasterKeyId after create is {attrs.get('KmsMasterKeyId')!r}, expected the key id "
        f"the template set, {key1['KeyId']!r} — SQS echoes the value as given, not an ARN"
    )
    assert attrs["KmsDataKeyReusePeriodSeconds"] == "70", (
        f"KmsDataKeyReusePeriodSeconds after create is "
        f"{attrs.get('KmsDataKeyReusePeriodSeconds')!r}, expected '70'"
    )
    _round_trip(sqs, queue_url, "stage-one-key-one")

    # ---- update in place: swap to key two, change the reuse period -----------------------
    cfn.update_stack(
        StackName=stack, TemplateBody=_TEMPLATE,
        Parameters=_params(queue_name, key2["KeyId"], 3600, "false"),
    )
    updated = _wait_terminal(cfn, stack)
    assert updated["StackStatus"] == "UPDATE_COMPLETE", (
        f"key-swap update reached {updated['StackStatus']!r}: {updated.get('StackStatusReason')!r}"
    )
    new_outputs = {o["OutputKey"]: o["OutputValue"] for o in updated.get("Outputs", [])}
    assert new_outputs["QueueUrl"] == queue_url and new_outputs["QueueArn"] == queue_arn, (
        f"mutable properties changed but the queue was replaced: url {new_outputs['QueueUrl']!r} "
        f"vs {queue_url!r}, arn {new_outputs['QueueArn']!r} vs {queue_arn!r}"
    )

    attrs = _get_attrs(sqs, queue_url)
    assert attrs["KmsMasterKeyId"] == key2["KeyId"], (
        f"KmsMasterKeyId after the swap is {attrs.get('KmsMasterKeyId')!r}, expected the key id "
        f"the update set, {key2['KeyId']!r}"
    )
    assert attrs["KmsDataKeyReusePeriodSeconds"] == "3600", (
        f"KmsDataKeyReusePeriodSeconds after the swap is "
        f"{attrs.get('KmsDataKeyReusePeriodSeconds')!r}, expected '3600'"
    )
    _round_trip(sqs, queue_url, "stage-two-key-two")

    # ---- update in place: drop KMS, switch to SSE-SQS -------------------------------------
    cfn.update_stack(
        StackName=stack, TemplateBody=_TEMPLATE,
        Parameters=_params(queue_name, key2["KeyId"], 3600, "true"),
    )
    final = _wait_terminal(cfn, stack)
    assert final["StackStatus"] == "UPDATE_COMPLETE", (
        f"SSE-SQS update reached {final['StackStatus']!r}: {final.get('StackStatusReason')!r}"
    )
    final_outputs = {o["OutputKey"]: o["OutputValue"] for o in final.get("Outputs", [])}
    assert final_outputs["QueueUrl"] == queue_url, (
        f"switching encryption mode changed the queue url to {final_outputs['QueueUrl']!r}, "
        f"expected the same {queue_url!r}"
    )

    attrs = _get_attrs(sqs, queue_url)
    assert "KmsMasterKeyId" not in attrs, (
        f"KmsMasterKeyId is still {attrs.get('KmsMasterKeyId')!r} after switching to "
        f"SqsManagedSseEnabled; it must disappear along with the KMS encryption it named"
    )
    assert attrs.get("SqsManagedSseEnabled") == "true", (
        f"SqsManagedSseEnabled after the switch is {attrs.get('SqsManagedSseEnabled')!r}, "
        f"expected 'true'"
    )
    _round_trip(sqs, queue_url, "stage-three-sse-sqs")

    # ---- delete leaves nothing behind: the queue is gone, not just the stack -------------
    _delete_stack_and_wait(cfn, stack)
    code, message = _error(lambda: sqs.get_queue_attributes(QueueUrl=queue_url, AttributeNames=["All"]))
    assert (code, message) == (
        "AWS.SimpleQueueService.NonExistentQueue", "The specified queue does not exist."
    ), (
        f"after stack delete, GetQueueAttributes({queue_url!r}) returned {code!r}: {message!r}, "
        f"expected an outright not-found"
    )
    code, message = _error(lambda: sqs.send_message(QueueUrl=queue_url, MessageBody="dead"))
    assert (code, message) == (
        "AWS.SimpleQueueService.NonExistentQueue", "The specified queue does not exist."
    ), (
        f"SendMessage on the deleted queue returned {code!r}: {message!r}, expected the same "
        f"outright not-found a read gives"
    )


def _params(queue_name: str, key_id: str, reuse_period: int, sse: str) -> list[dict[str, str]]:
    return [
        {"ParameterKey": "QueueName", "ParameterValue": queue_name},
        {"ParameterKey": "KmsKeyId", "ParameterValue": key_id},
        {"ParameterKey": "ReusePeriod", "ParameterValue": str(reuse_period)},
        {"ParameterKey": "SqsManagedSse", "ParameterValue": sse},
    ]


def _create_key(ctx, kms, label: str) -> dict[str, str]:
    """A customer-managed key under the default (root-trust) key policy, torn down to
    PendingDeletion."""
    created = kms.create_key(
        Description=f"sim2real behavioral key {label}",
        Tags=[{"TagKey": "sim2real", "TagValue": CHECK}],
    )["KeyMetadata"]
    key_id = created["KeyId"]
    ctx.on_cleanup(lambda: kms.schedule_key_deletion(KeyId=key_id, PendingWindowInDays=7))
    return {"KeyId": key_id}


def _get_attrs(sqs, queue_url: str) -> dict[str, str]:
    return sqs.get_queue_attributes(QueueUrl=queue_url, AttributeNames=["All"])["Attributes"]


def _round_trip(sqs, queue_url: str, body: str) -> None:
    sent = sqs.send_message(QueueUrl=queue_url, MessageBody=body)["MessageId"]
    got = _poll_until(
        lambda: sqs.receive_message(
            QueueUrl=queue_url, MaxNumberOfMessages=1, WaitTimeSeconds=5
        ).get("Messages", []),
        lambda ms: bool(ms), timeout_s=60.0, interval_s=2.0,
        description=f"a message on {queue_url!r} encrypted under the stage's active key/mode",
    )
    assert got[0]["MessageId"] == sent, (
        f"received message id {got[0]['MessageId']!r}, expected the sent {sent!r}"
    )
    assert got[0]["Body"] == body, f"received body {got[0]['Body']!r}, expected {body!r}"
    sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=got[0]["ReceiptHandle"])


def _error(fn):
    """(Error.Code, Error.Message) of the ClientError fn() raises; an unexpected success fails."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


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
