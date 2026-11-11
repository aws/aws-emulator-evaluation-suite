"""lambda-sdk-sqs-receivemessage-missing-permission-denied."""
from __future__ import annotations

import io
import json
import time
import zipfile
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "lambda-sdk-sqs-receivemessage-missing-permission-denied"
GROUP = "permission-boundary"
SERVICES = ["events", "lambda", "sqs"]

_HANDLER = """
import boto3

def handler(event, context):
    client = boto3.client('sqs')
    try:
        resp = client.receive_message(
            QueueUrl=event['queue_url'], MaxNumberOfMessages=1, WaitTimeSeconds=2,
        )
        return {'ok': True, 'count': len(resp.get('Messages', [])), 'messages': resp.get('Messages', [])}
    except Exception as e:
        code = getattr(e, 'response', {}).get('Error', {}).get('Code', str(e))
        return {'ok': False, 'code': code}
"""


@tags("axis:rejection", "cap:c2", "cap:c3", "cap:c7", "concern:data-plane", "concern:e2e", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """Lambda role lacking sqs:ReceiveMessage fails with AccessDenied when directly polling."""
    sqs = ctx.client("sqs")
    queue_url = sqs.create_queue(
        QueueName=ctx.unique_name("sim2real-behav-q-"),
        tags={"sim2real-check": CHECK},
    )["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=queue_url))

    body_text = "sim2real-receive-denied-body"
    sqs.send_message(QueueUrl=queue_url, MessageBody=body_text)

    denied_role_arn = _create_role(ctx, [], "receive-denied")
    denied_fn = _create_function(ctx, denied_role_arn, _HANDLER, "receive-denied")

    denied_body = _invoke(ctx, denied_fn, {"queue_url": queue_url})
    assert denied_body["ok"] is False, (
        f"a role lacking sqs:ReceiveMessage must have the SDK call fail inside the function; "
        f"got ok={denied_body['ok']!r}"
    )
    assert denied_body["code"] == "AccessDenied", (
        f"expected AccessDenied for the missing sqs:ReceiveMessage permission, got "
        f"{denied_body['code']!r}"
    )

    # effect absent: the message was never consumed by the denied call, it is still there
    still_there = sqs.receive_message(QueueUrl=queue_url, MaxNumberOfMessages=1, WaitTimeSeconds=5)
    msgs = still_there.get("Messages", [])
    assert len(msgs) == 1, (
        f"the denied call must not have consumed the message; expected exactly 1 message still "
        f"in the queue, got {len(msgs)}"
    )
    assert msgs[0]["Body"] == body_text, (
        f"expected the untouched original message body {body_text!r}, got {msgs[0]['Body']!r}"
    )
    sqs.change_message_visibility(
        QueueUrl=queue_url, ReceiptHandle=msgs[0]["ReceiptHandle"], VisibilityTimeout=0
    )

    # positive control in the same file: a role WITH sqs:ReceiveMessage does read the message
    allowed_role_arn = _create_role(
        ctx, [{"Effect": "Allow", "Action": "sqs:ReceiveMessage", "Resource": "*"}], "receive-allowed"
    )
    allowed_fn = _create_function(ctx, allowed_role_arn, _HANDLER, "receive-allowed")
    allowed_body = _poll_until(
        lambda: _invoke(ctx, allowed_fn, {"queue_url": queue_url}),
        lambda b: b.get("ok") is True and b.get("count", 0) >= 1,
        timeout_s=30.0,
        interval_s=2.0,
    )
    assert allowed_body["messages"][0]["Body"] == body_text, (
        f"the positive-control role has sqs:ReceiveMessage, so it must read the same message "
        f"{body_text!r}; got {allowed_body['messages'][0]['Body']!r}"
    )
    sqs.delete_message(
        QueueUrl=queue_url, ReceiptHandle=allowed_body["messages"][0]["ReceiptHandle"]
    )

    # the delete above is otherwise unasserted: prove it landed via an independent read
    drained = sqs.receive_message(QueueUrl=queue_url, MaxNumberOfMessages=1, WaitTimeSeconds=5)
    assert not drained.get("Messages"), (
        f"the message was deleted after the positive-control read, so an independent receive "
        f"must now find the queue empty; got {drained.get('Messages')!r}"
    )


_LAMBDA_TRUST_POLICY = json.dumps(
    {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
)

_LOGS_POLICY_ARN = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"


def _poll_until(probe, predicate, timeout_s=30.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last={last!r}")


def _create_role(ctx: Any, statements: list, suffix: str) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name(f"sim2real-behav-role-{suffix}-")
    iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=_LAMBDA_TRUST_POLICY,
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: _delete_role(ctx, role_name))
    iam.attach_role_policy(RoleName=role_name, PolicyArn=_LOGS_POLICY_ARN)
    if statements:
        iam.put_role_policy(
            RoleName=role_name,
            PolicyName="inline-under-test",
            PolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": statements}),
        )
    return iam.get_role(RoleName=role_name)["Role"]["Arn"]


def _delete_role(ctx: Any, role_name: str) -> None:
    iam = ctx.client("iam")
    try:
        for pol in iam.list_attached_role_policies(RoleName=role_name).get("AttachedPolicies", []):
            iam.detach_role_policy(RoleName=role_name, PolicyArn=pol["PolicyArn"])
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise
    try:
        for pol in iam.list_role_policies(RoleName=role_name).get("PolicyNames", []):
            iam.delete_role_policy(RoleName=role_name, PolicyName=pol)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise
    try:
        iam.delete_role(RoleName=role_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _zip_handler(handler_code: str) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("index.py", handler_code)
    return buf.getvalue()


def _create_function(ctx: Any, role_arn: str, handler_code: str, suffix: str, timeout: int = 30) -> str:
    lam = ctx.client("lambda")
    name = ctx.unique_name(f"sim2real-behav-fn-{suffix}-")
    zip_bytes = _zip_handler(handler_code)
    deadline = time.monotonic() + 60
    last_err = None
    while time.monotonic() < deadline:
        try:
            ctx.on_cleanup(lambda _n=name: _delete_lambda_log_group(ctx, _n))
            lam.create_function(
                FunctionName=name,
                Runtime="python3.12",
                Role=role_arn,
                Handler="index.handler",
                Code={"ZipFile": zip_bytes},
                Timeout=timeout,
                Tags={"sim2real-check": CHECK},
            )
            break
        except ClientError as e:
            if e.response["Error"]["Code"] == "InvalidParameterValueException":
                last_err = e
                time.sleep(3)
                continue
            raise
    else:
        raise AssertionError(f"function {name} never became creatable: {last_err}")
    ctx.on_cleanup(lambda: lam.delete_function(FunctionName=name))
    _wait_function_active(ctx, name)
    return name


def _wait_function_active(ctx: Any, name: str, timeout_s: float = 90.0) -> None:
    lam = ctx.client("lambda")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        cfg = lam.get_function_configuration(FunctionName=name)
        state = cfg["State"]
        if state == "Active":
            return
        if state == "Failed":
            raise AssertionError(f"function {name} entered Failed state: {cfg}")
        time.sleep(2)
    raise AssertionError(f"function {name} did not become Active within {timeout_s}s")


def _invoke(ctx: Any, name: str, payload: dict) -> dict:
    lam = ctx.client("lambda")
    resp = lam.invoke(
        FunctionName=name,
        Payload=json.dumps(payload).encode("utf-8"),
        InvocationType="RequestResponse",
    )
    return json.loads(resp["Payload"].read())


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
