"""lambda-sdk-sqs-missing-receivemessage-permission-negative."""
from __future__ import annotations

import io
import json
import time
import zipfile
from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "lambda-sdk-sqs-missing-receivemessage-permission-negative"
GROUP = "overly-permissive"
SERVICES = ["lambda", "s3", "sqs"]

_HANDLER_CODE = """
import boto3
from botocore.exceptions import ClientError

def handler(event, context):
    sqs = boto3.client("sqs")
    try:
        resp = sqs.receive_message(QueueUrl=event["queue_url"], MaxNumberOfMessages=1, WaitTimeSeconds=5)
        msgs = resp.get("Messages", [])
        if not msgs:
            return {"status": "empty"}
        return {"status": "ok", "body": msgs[0]["Body"]}
    except ClientError as err:
        return {"status": "error", "code": err.response["Error"]["Code"]}
"""


@tags("axis:rejection", "cap:c2", "cap:c3", "cap:c7", "concern:data-plane", "concern:e2e", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """A role lacking sqs:ReceiveMessage gets AccessDenied and the queue polls to one visible
    message; a role WITH the permission (positive control) then receives that message."""
    sqs = ctx.client("sqs")
    queue_url = sqs.create_queue(
        QueueName=ctx.unique_name("sim2real-behav-recvdenied-"), tags=_resource_tags()
    )["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=queue_url))
    queue_arn = sqs.get_queue_attributes(QueueUrl=queue_url, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]

    body = "receive-denied-fixture"
    sqs.send_message(QueueUrl=queue_url, MessageBody=body)

    # Negative: role can only see queue attributes, not receive messages.
    denied_role_arn = _create_lambda_role(
        ctx, [{"Effect": "Allow", "Action": ["sqs:GetQueueAttributes"], "Resource": queue_arn}]
    )
    denied_fn = _create_lambda_function(ctx, denied_role_arn, _HANDLER_CODE)
    denied_result = _invoke_lambda(ctx, denied_fn, {"queue_url": queue_url})
    assert denied_result["status"] == "error", f"expected the denied invoke to error, got {denied_result!r}"
    assert denied_result["code"] == "AccessDenied", f"expected AccessDenied, got {denied_result['code']!r}"

    # Effect must be absent: the message is still sitting in the queue, unconsumed.
    _poll_queue_counters(ctx, sqs, queue_url, {"ApproximateNumberOfMessages": "1"})

    # Positive control: a role WITH sqs:ReceiveMessage actually receives the message.
    allowed_role_arn = _create_lambda_role(
        ctx,
        [
            {
                "Effect": "Allow",
                "Action": ["sqs:ReceiveMessage", "sqs:GetQueueAttributes"],
                "Resource": queue_arn,
            }
        ],
    )
    allowed_fn = _create_lambda_function(ctx, allowed_role_arn, _HANDLER_CODE)
    allowed_result = _invoke_lambda(ctx, allowed_fn, {"queue_url": queue_url})
    assert allowed_result["status"] == "ok", f"positive control failed: {allowed_result}"
    assert allowed_result["body"] == body, (
        f"expected the positive control to receive {body!r}, got {allowed_result['body']!r}"
    )


# ===== helpers =====
_MANAGED_TAG_KEY = "sim2real:managed"


def _resource_tags() -> dict[str, str]:
    return {_MANAGED_TAG_KEY: "true"}


def _resource_tags_kv() -> list[dict[str, str]]:
    return [{"Key": k, "Value": v} for k, v in _resource_tags().items()]


_LAMBDA_TRUST_POLICY = json.dumps(
    {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
)


def _zip_code(code: str) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("lambda_function.py", code)
    return buf.getvalue()


def _create_lambda_role(ctx, statements: list[dict[str, Any]]) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-behav-role-")
    role = iam.create_role(
        RoleName=role_name, AssumeRolePolicyDocument=_LAMBDA_TRUST_POLICY, Tags=_resource_tags_kv()
    )
    role_arn = role["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))

    basic_policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=basic_policy_arn)
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=basic_policy_arn))

    policy_name = ctx.unique_name("sim2real-behav-policy-")
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName=policy_name,
        PolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": statements}),
    )
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name))
    return role_arn


def _create_lambda_function(ctx, role_arn: str, code: str, env: dict[str, str] | None = None, timeout: int = 30) -> str:
    lam = ctx.client("lambda")
    fn_name = ctx.unique_name("sim2real-behav-fn-")
    kwargs: dict[str, Any] = dict(
        FunctionName=fn_name,
        Runtime="python3.12",
        Role=role_arn,
        Handler="lambda_function.handler",
        Code={"ZipFile": _zip_code(code)},
        Timeout=timeout,
        Publish=True,
        Tags=_resource_tags(),
    )
    if env:
        kwargs["Environment"] = {"Variables": env}

    last_err: Exception | None = None
    ctx.on_cleanup(lambda _n=fn_name: _delete_lambda_log_group(ctx, _n))
    # A new execution role is not assumable by Lambda at once: retry its InvalidParameterValue to a deadline.
    deadline = time.monotonic() + _budget_s(ctx, 60.0)
    while time.monotonic() < deadline:
        try:
            lam.create_function(**kwargs)
            break
        except lam.exceptions.InvalidParameterValueException as err:
            last_err = err
            time.sleep(2)
    else:
        raise AssertionError(f"create_function never succeeded (role propagation?): {last_err}")

    ctx.on_cleanup(lambda: lam.delete_function(FunctionName=fn_name))
    lam.get_waiter("function_active_v2").wait(FunctionName=fn_name, WaiterConfig={"Delay": 2, "MaxAttempts": 150})
    return fn_name


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _poll_queue_counters(ctx, sqs, queue_url, expected, cap_s=90.0):
    """Poll GetQueueAttributes until every named counter equals its expected string value.

    The ApproximateNumberOf* counters may lag up to a minute after producers stop
    (SQS GetQueueAttributes docs), so a single read is not a verdict."""
    start = time.monotonic()
    budget_s = _budget_s(ctx, cap_s)
    stop = start + min(cap_s, budget_s)
    while True:
        attrs = sqs.get_queue_attributes(QueueUrl=queue_url, AttributeNames=list(expected))["Attributes"]
        observed = {name: attrs.get(name) for name in expected}
        if observed == expected:
            return attrs
        if time.monotonic() >= stop:
            if budget_s < cap_s:
                raise TimeoutError(
                    f"the check's time budget ran out after {time.monotonic() - start:.1f}s, before "
                    f"the {cap_s}s counter wait ended (last observed {observed}); not graded"
                )
            raise AssertionError(f"queue counters never reached {expected} within {cap_s}s; last observed {observed}")
        time.sleep(3)


def _invoke_lambda(ctx, fn_name: str, payload: dict[str, Any]) -> dict[str, Any]:
    lam = ctx.client("lambda")
    resp = lam.invoke(
        FunctionName=fn_name,
        InvocationType="RequestResponse",
        Payload=json.dumps(payload).encode("utf-8"),
    )
    body = json.loads(resp["Payload"].read())
    if resp.get("FunctionError"):
        raise AssertionError(f"lambda invocation errored: {body}")
    return body


def _delete_lambda_log_group(ctx, function_name: str) -> None:
    """Delete the log group Lambda creates on a function's first log line; one never created is fine."""
    try:
        ctx.client("logs").delete_log_group(logGroupName=f"/aws/lambda/{function_name}")
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
