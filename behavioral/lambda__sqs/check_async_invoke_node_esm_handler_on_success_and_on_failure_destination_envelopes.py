"""async-invoke-node-esm-handler-on-success-and-on-failure-destination-envelopes."""
from __future__ import annotations

import json
import time
import zipfile
from io import BytesIO

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "async-invoke-node-esm-handler-on-success-and-on-failure-destination-envelopes"
GROUP = "event-propagation"
SERVICES = ["lambda", "sqs"]

_TAGS = {"sim2real:managed": "true"}

# An ESM handler, `export const handler`, with no bundling.
_HANDLER_MJS = r"""
export const handler = async (event) => {
  if (event.fail) {
    throw new Error(event.marker);
  }
  return { echo: event.marker };
};
"""


def _teardown(undo, *not_found: str):
    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _await_message(ctx, sqs, url: str, *, timeout_s: float, description: str) -> dict:
    timeout_s = _budget_s(ctx, timeout_s)
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        msgs = sqs.receive_message(QueueUrl=url, MaxNumberOfMessages=1, WaitTimeSeconds=5).get(
            "Messages", [])
        if msgs:
            sqs.delete_message(QueueUrl=url, ReceiptHandle=msgs[0]["ReceiptHandle"])
            return msgs[0]
    if _budget_spent(ctx):
        raise TimeoutError(f"{description}: the run budget ended first; not graded")
    raise AssertionError(f"{description}: nothing arrived within {timeout_s:.0f}s")


def _wait_active(ctx, lam, fn: str, timeout_s=150.0) -> dict:
    timeout_s = _budget_s(ctx, timeout_s)
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = lam.get_function_configuration(FunctionName=fn)
        if last["State"] == "Failed":
            raise AssertionError(
                f"{fn} reached State=Failed: {last.get('StateReasonCode')!r} "
                f"{last.get('StateReason')!r}"
            )
        if last["State"] == "Active":
            return last
        time.sleep(2.0)
    if _budget_spent(ctx):
        raise TimeoutError(
            f"{fn} stayed State={last and last.get('State')!r}: the run budget ended first; not graded")
    raise AssertionError(f"{fn} stayed State={last and last.get('State')!r} for {timeout_s}s")


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "concern:e2e", "concern:eventing",
      "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """An async invoke of a Node.js ESM handler delivers the documented destination envelope on
    both outcomes: OnSuccess carries the handler's return value, and OnFailure's responsePayload
    carries the Node.js runtime's own errorType/errorMessage/trace shape for a thrown Error.

    Reference: https://docs.aws.amazon.com/lambda/latest/dg/invocation-async.html
    """
    sqs = ctx.client("sqs")
    lam = ctx.client("lambda")
    iam = ctx.client("iam")

    success_q = ctx.unique_name("sim2real-asyncdest-okq-")
    success_url = sqs.create_queue(QueueName=success_q, tags=dict(_TAGS))["QueueUrl"]
    ctx.on_cleanup(_teardown(lambda: sqs.delete_queue(QueueUrl=success_url),
                             "AWS.SimpleQueueService.NonExistentQueue"))
    success_arn = sqs.get_queue_attributes(
        QueueUrl=success_url, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]

    failure_q = ctx.unique_name("sim2real-asyncdest-failq-")
    failure_url = sqs.create_queue(QueueName=failure_q, tags=dict(_TAGS))["QueueUrl"]
    ctx.on_cleanup(_teardown(lambda: sqs.delete_queue(QueueUrl=failure_url),
                             "AWS.SimpleQueueService.NonExistentQueue"))
    failure_arn = sqs.get_queue_attributes(
        QueueUrl=failure_url, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]

    role_name = ctx.unique_name("sim2real-asyncdest-role-")
    trust = {"Version": "2012-10-17", "Statement": [{
        "Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"},
        "Action": "sts:AssumeRole"}]}
    role_arn = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust),
                                Tags=[{"Key": k, "Value": v} for k, v in _TAGS.items()])["Role"]["Arn"]
    ctx.on_cleanup(_teardown(lambda: iam.delete_role(RoleName=role_name), "NoSuchEntity"))
    basic = f"arn:{role_arn.split(':')[1]}:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=basic)
    ctx.on_cleanup(_teardown(lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=basic),
                             "NoSuchEntity"))
    iam.put_role_policy(RoleName=role_name, PolicyName="inline", PolicyDocument=json.dumps({
        "Version": "2012-10-17", "Statement": [
            {"Effect": "Allow", "Action": "sqs:SendMessage",
             "Resource": [success_arn, failure_arn]},
        ]}))
    ctx.on_cleanup(_teardown(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName="inline"),
                             "NoSuchEntity"))

    fn_name = ctx.unique_name("sim2real-asyncdest-fn-")
    group = f"/aws/lambda/{fn_name}"
    zip_buf = BytesIO()
    with zipfile.ZipFile(zip_buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("index.mjs", _HANDLER_MJS)
    deadline = time.monotonic() + _budget_s(ctx, 90.0)
    while True:
        try:
            lam.create_function(
                FunctionName=fn_name, Runtime="nodejs22.x", Role=role_arn,
                Handler="index.handler", Code={"ZipFile": zip_buf.getvalue()},
                Timeout=10, MemorySize=256, Tags=_TAGS,
            )
            break
        except ClientError as exc:
            propagating = (exc.response["Error"]["Code"] == "InvalidParameterValueException"
                           and "assumed" in str(exc))
            if not propagating or time.monotonic() > deadline:
                if propagating and _budget_spent(ctx):
                    raise TimeoutError(
                        "CreateFunction: the run budget ended first while the execution role "
                        "was still propagating; not graded"
                    ) from exc
                raise
            time.sleep(2.0)

    def _reap_log_group() -> None:
        logs = ctx.client("logs")
        deadline2 = time.monotonic() + 45
        absent = 0
        while absent < 3:
            groups = logs.describe_log_groups(logGroupNamePrefix=group)["logGroups"]
            if any(g["logGroupName"] == group for g in groups):
                absent = 0
                try:
                    logs.delete_log_group(logGroupName=group)
                except ClientError as exc:
                    if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                        raise
            else:
                absent += 1
            if absent < 3:
                assert time.monotonic() < deadline2, "lambda log group never settled absent"
                time.sleep(5)

    ctx.on_cleanup(_reap_log_group)
    ctx.on_cleanup(_teardown(lambda: lam.delete_function(FunctionName=fn_name),
                             "ResourceNotFoundException"))
    _wait_active(ctx, lam, fn_name)

    lam.put_function_event_invoke_config(
        FunctionName=fn_name, MaximumRetryAttempts=0, MaximumEventAgeInSeconds=60,
        DestinationConfig={
            "OnSuccess": {"Destination": success_arn},
            "OnFailure": {"Destination": failure_arn},
        },
    )
    ctx.on_cleanup(_teardown(
        lambda: lam.delete_function_event_invoke_config(FunctionName=fn_name),
        "ResourceNotFoundException"))

    ok_marker = ctx.unique_name("ok-")
    ok_payload = {"marker": ok_marker, "fail": False}
    ok_resp = lam.invoke(FunctionName=fn_name, InvocationType="Event",
                         Payload=json.dumps(ok_payload).encode())
    assert ok_resp["StatusCode"] == 202, f"async invoke returned {ok_resp['StatusCode']!r}"

    fail_marker = ctx.unique_name("fail-")
    fail_payload = {"marker": fail_marker, "fail": True}
    fail_resp = lam.invoke(FunctionName=fn_name, InvocationType="Event",
                           Payload=json.dumps(fail_payload).encode())
    assert fail_resp["StatusCode"] == 202, f"async invoke returned {fail_resp['StatusCode']!r}"

    ok_msg = _await_message(ctx, sqs, success_url, timeout_s=150, description="the OnSuccess record")
    ok_record = json.loads(ok_msg["Body"])
    assert ok_record.get("version") == "1.0", f"record version was {ok_record.get('version')!r}"
    ok_rc = ok_record.get("requestContext", {})
    assert ok_rc.get("condition") == "Success", (
        f"OnSuccess requestContext.condition was {ok_rc.get('condition')!r}, expected 'Success'"
    )
    assert ok_record.get("requestPayload") == ok_payload, (
        f"OnSuccess requestPayload was {ok_record.get('requestPayload')!r}, expected {ok_payload!r}"
    )
    ok_resp_ctx = ok_record.get("responseContext", {})
    assert ok_resp_ctx.get("statusCode") == 200, f"OnSuccess responseContext was {ok_resp_ctx!r}"
    assert "functionError" not in ok_resp_ctx, (
        f"a success record must carry no functionError, got {ok_resp_ctx!r}"
    )
    assert ok_record.get("responsePayload") == {"echo": ok_marker}, (
        f"OnSuccess responsePayload was {ok_record.get('responsePayload')!r}, expected the "
        f"handler's return value {{'echo': {ok_marker!r}}}"
    )

    fail_msg = _await_message(ctx, sqs, failure_url, timeout_s=150, description="the OnFailure record")
    fail_record = json.loads(fail_msg["Body"])
    fail_rc = fail_record.get("requestContext", {})
    assert fail_rc.get("condition") == "RetriesExhausted", (
        f"OnFailure requestContext.condition was {fail_rc.get('condition')!r}, expected "
        f"'RetriesExhausted' with MaximumRetryAttempts=0"
    )
    assert fail_record.get("requestPayload") == fail_payload, (
        f"OnFailure requestPayload was {fail_record.get('requestPayload')!r}, expected "
        f"{fail_payload!r}"
    )
    fail_resp_ctx = fail_record.get("responseContext", {})
    assert fail_resp_ctx.get("functionError") == "Unhandled", (
        f"OnFailure responseContext.functionError was {fail_resp_ctx.get('functionError')!r}, "
        f"expected 'Unhandled' for an uncaught exception"
    )
    fail_payload_body = fail_record.get("responsePayload", {})
    assert fail_payload_body.get("errorType") == "Error", (
        f"a thrown `new Error(...)` in Node.js reports errorType 'Error', got "
        f"{fail_payload_body.get('errorType')!r}"
    )
    assert fail_payload_body.get("errorMessage") == fail_marker, (
        f"errorMessage was {fail_payload_body.get('errorMessage')!r}, expected the thrown "
        f"Error's message {fail_marker!r}"
    )
    assert isinstance(fail_payload_body.get("trace"), list) and fail_payload_body["trace"], (
        f"the Node.js runtime's error payload must carry a non-empty 'trace' stack list, got "
        f"{fail_payload_body.get('trace')!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
