"""events-role-trust-policy-allows-assume-for-cloudfront-target."""
from __future__ import annotations

import json
import time
import zipfile
import io
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "events-role-trust-policy-allows-assume-for-cloudfront-target"
GROUP = "permission-boundary"
SERVICES = ["cloudfront", "events"]


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "concern:e2e", "concern:eventing", "dp:api", "plane:data")
def run(ctx) -> None:
    """A role trusting events.amazonaws.com, passed as PutTargets RoleArn, lets EventBridge
    assume it and invoke a CloudFront-invalidation-purpose Lambda (Lambda + SQS + Events
    support IAM execution roles as an alternative to Lambda resource-based policies)."""
    events = ctx.client("events")

    queue_url, queue_arn = _create_queue(ctx)

    lambda_role_arn = _create_role(
        ctx,
        "lambda-exec",
        "lambda.amazonaws.com",
        {
            "Version": "2012-10-17",
            "Statement": [
                {"Effect": "Allow", "Action": "cloudfront:ListDistributions", "Resource": "*"},
                {"Effect": "Allow", "Action": "sqs:SendMessage", "Resource": queue_arn},
                {
                    "Effect": "Allow",
                    "Action": ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"],
                    "Resource": "*",
                },
            ],
        },
    )

    code = f"""
import boto3, json
def lambda_handler(event, context):
    cf = boto3.client("cloudfront")
    cf.list_distributions(MaxItems="1")
    sqs = boto3.client("sqs")
    sqs.send_message(QueueUrl="{queue_url}", MessageBody=json.dumps({{
        "invoked": True, "requestId": event.get("detail", {{}}).get("requestId")
    }}))
"""
    fn_arn = _create_lambda(ctx, lambda_role_arn, code, "invalidation-fn")

    events_role_arn = _create_role(
        ctx,
        "events-target",
        "events.amazonaws.com",
        {
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Action": "lambda:InvokeFunction", "Resource": fn_arn}],
        },
    )

    rule_name = ctx.unique_name("sim2real-cf-trust-rule-")
    events.put_rule(
        Name=rule_name,
        EventPattern=json.dumps(
            {"source": ["sim2real.cloudfront.test"], "detail-type": ["CloudFront Cache Purge Requested"]}
        ),
    )
    ctx.on_cleanup(lambda: events.delete_rule(Name=rule_name))
    _retry_on_role_propagation(
        lambda: events.put_targets(
            Rule=rule_name,
            Targets=[{"Id": "invalidation-target", "Arn": fn_arn, "RoleArn": events_role_arn}],
        )
    )
    ctx.on_cleanup(lambda: events.remove_targets(Rule=rule_name, Ids=["invalidation-target"]))

    # The events-target role's inline invoke-permission may not yet be visible to EventBridge
    # the moment the rule first fires, even though PutTargets already validated its trust policy.
    # Rather than guess a fixed extra delay, re-fire with a fresh event id on a bounded deadline.
    msg = None
    for _ in range(4):
        request_id = ctx.unique_name("req-")
        events.put_events(
            Entries=[
                {
                    "Source": "sim2real.cloudfront.test",
                    "DetailType": "CloudFront Cache Purge Requested",
                    "Detail": json.dumps({"requestId": request_id, "distributionId": "EDFAKE0000000EX"}),
                }
            ]
        )
        msg = _receive_matching_message(ctx, queue_url, "requestId", request_id, timeout_s=30)
        if msg is not None:
            break
    else:
        raise AssertionError("no message for any of 4 re-fired events arrived within 30s each")

    assert msg["invoked"] is True, (
        f"expected the CloudFront-purpose Lambda to have run and reported invoked=True, got {msg!r}"
    )


def _create_queue(ctx) -> tuple[str, str]:
    sqs = ctx.client("sqs")
    url = sqs.create_queue(
        QueueName=ctx.unique_name("sim2real-cf-trust-q-"), tags={"sim2real:managed": "true"}
    )["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))
    arn = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]
    return url, arn


def _create_role(ctx, kind: str, trust_principal: str, policy_doc: dict[str, Any]) -> str:
    iam = ctx.client("iam")
    name = ctx.unique_name(f"sim2real-cf-{kind}-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": trust_principal}, "Action": "sts:AssumeRole"}],
    }
    resp = iam.create_role(
        RoleName=name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
    )
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=name))
    iam.put_role_policy(RoleName=name, PolicyName="inline", PolicyDocument=json.dumps(policy_doc))
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=name, PolicyName="inline"))
    return resp["Role"]["Arn"]


def _retry_on_role_propagation(fn, *, timeout_s: float = 45.0, interval_s: float = 3.0):
    """A freshly-created role's trust policy is not yet visible to EventBridge; retry PutTargets
    (it answers ValidationException) until IAM propagation catches up or the deadline passes."""
    deadline = time.monotonic() + timeout_s
    last_exc = None
    while time.monotonic() < deadline:
        try:
            return fn()
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ValidationException":
                raise
            last_exc = exc
            time.sleep(interval_s)
    raise last_exc


def _zip_code(code: str) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("lambda_function.py", code)
    return buf.getvalue()


def _create_lambda(ctx, role_arn: str, code: str, kind: str) -> str:
    lam = ctx.client("lambda")
    name = ctx.unique_name(f"sim2real-{kind}-")
    last_err = None
    for _ in range(10):
        try:
            ctx.on_cleanup(lambda _n=name: _delete_lambda_log_group(ctx, _n))
            resp = lam.create_function(
                FunctionName=name,
                Runtime="python3.12",
                Role=role_arn,
                Handler="lambda_function.lambda_handler",
                Code={"ZipFile": _zip_code(code)},
                Timeout=30,
                Tags={"sim2real:managed": "true"},
            )
            break
        except Exception as exc:  # noqa: BLE001 - role propagation retry
            last_err = exc
            time.sleep(3)
    else:
        raise last_err
    ctx.on_cleanup(lambda: lam.delete_function(FunctionName=name))
    waiter = lam.get_waiter("function_active_v2")
    waiter.wait(FunctionName=name, WaiterConfig={"Delay": 2, "MaxAttempts": 150})
    return resp["FunctionArn"]


def _receive_matching_message(
    ctx, queue_url: str, key: str, value: str, timeout_s: float = 60.0
) -> dict[str, Any] | None:
    """The first message whose body[key] is value within timeout_s, else None."""
    sqs = ctx.client("sqs")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        resp = sqs.receive_message(QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=5)
        for m in resp.get("Messages", []):
            body = json.loads(m["Body"])
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=m["ReceiptHandle"])
            if body.get(key) == value:
                return body
    return None


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
