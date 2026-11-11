"""eventbridge-role-without-events-trust-rejected."""
from __future__ import annotations

import json
import time
import zipfile
import io
from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "eventbridge-role-without-events-trust-rejected"
GROUP = "overly-permissive"
SERVICES = ["cloudfront", "events"]


@tags("axis:negative-delivery", "cap:c3", "concern:data-plane", "concern:eventing", "dp:api", "plane:data")
def run(ctx) -> None:
    """PutTargets accepts a RoleArn whose trust policy omits events.amazonaws.com, but a matching event never reaches
    the CloudFront-invalidation Lambda through it, while a second rule whose role trusts EventBridge delivers."""
    events = ctx.client("events")

    queue_url, queue_arn = _create_queue(ctx)

    lambda_role_arn = _create_role(
        ctx,
        "lambda-exec",
        "lambda.amazonaws.com",
        {
            "Version": "2012-10-17",
            "Statement": [
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
    sqs = boto3.client("sqs")
    sqs.send_message(QueueUrl="{queue_url}", MessageBody=json.dumps({{
        "invoked": True, "requestId": event.get("detail", {{}}).get("requestId")
    }}))
"""
    fn_arn = _create_lambda(ctx, lambda_role_arn, code)

    # A role EventBridge is allowed to invoke Lambda with (trusts events.amazonaws.com).
    good_role_arn = _create_role(
        ctx,
        "good-target",
        "events.amazonaws.com",
        {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "lambda:InvokeFunction", "Resource": fn_arn}]},
    )
    # A role with the exact same permissions but that trusts only lambda.amazonaws.com --
    # EventBridge can never assume it.
    bad_role_arn = _create_role(
        ctx,
        "bad-target",
        "lambda.amazonaws.com",
        {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "lambda:InvokeFunction", "Resource": fn_arn}]},
    )

    events = ctx.client("events")
    rule_good = ctx.unique_name("sim2real-cf-good-rule-")
    rule_bad = ctx.unique_name("sim2real-cf-bad-rule-")
    events.put_rule(
        Name=rule_good,
        EventPattern=json.dumps({"source": ["sim2real.cloudfront.trust"], "detail": {"scenario": ["good"]}}),
    )
    ctx.on_cleanup(lambda: events.delete_rule(Name=rule_good))
    events.put_rule(
        Name=rule_bad,
        EventPattern=json.dumps({"source": ["sim2real.cloudfront.trust"], "detail": {"scenario": ["bad"]}}),
    )
    ctx.on_cleanup(lambda: events.delete_rule(Name=rule_bad))

    _put_targets_with_retry(events, rule_good, [{"Id": "t", "Arn": fn_arn, "RoleArn": good_role_arn}])
    ctx.on_cleanup(lambda: events.remove_targets(Rule=rule_good, Ids=["t"]))
    _put_targets_with_retry(events, rule_bad, [{"Id": "t", "Arn": fn_arn, "RoleArn": bad_role_arn}])
    ctx.on_cleanup(lambda: events.remove_targets(Rule=rule_bad, Ids=["t"]))

    bad_request_id = ctx.unique_name("bad-req-")
    good_request_id = ctx.unique_name("good-req-")

    events.put_events(
        Entries=[
            {
                "Source": "sim2real.cloudfront.trust",
                "DetailType": "CloudFront Cache Purge Requested",
                "Detail": json.dumps({"scenario": "bad", "requestId": bad_request_id}),
            }
        ]
    )
    assert not _message_arrives(ctx, queue_url, "requestId", bad_request_id, timeout_s=30), (
        "Lambda was invoked even though the target role does not trust events.amazonaws.com"
    )

    events.put_events(
        Entries=[
            {
                "Source": "sim2real.cloudfront.trust",
                "DetailType": "CloudFront Cache Purge Requested",
                "Detail": json.dumps({"scenario": "good", "requestId": good_request_id}),
            }
        ]
    )
    assert _message_arrives(ctx, queue_url, "requestId", good_request_id, timeout_s=90), (
        "positive control with a correctly-trusted role never delivered"
    )


def _create_queue(ctx) -> tuple[str, str]:
    sqs = ctx.client("sqs")
    url = sqs.create_queue(QueueName=ctx.unique_name("sim2real-cf-trust2-q-"))["QueueUrl"]
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
    resp = iam.create_role(RoleName=name, AssumeRolePolicyDocument=json.dumps(trust))
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=name))
    iam.put_role_policy(RoleName=name, PolicyName="inline", PolicyDocument=json.dumps(policy_doc))
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=name, PolicyName="inline"))
    return resp["Role"]["Arn"]


def _zip_code(code: str) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("lambda_function.py", code)
    return buf.getvalue()


def _create_lambda(ctx, role_arn: str, code: str) -> str:
    lam = ctx.client("lambda")
    name = ctx.unique_name("sim2real-invalidation-fn-")
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
            )
            break
        except Exception as exc:  # noqa: BLE001
            last_err = exc
            time.sleep(3)
    else:
        raise last_err
    ctx.on_cleanup(lambda: lam.delete_function(FunctionName=name))
    lam.get_waiter("function_active_v2").wait(FunctionName=name, WaiterConfig={"Delay": 2, "MaxAttempts": 150})
    return resp["FunctionArn"]


def _put_targets_with_retry(events, rule: str, targets: list[dict[str, Any]], timeout_s: float = 30.0) -> None:
    # IAM role/policy propagation is eventually consistent; retry until EventBridge's
    # control plane can resolve the freshly-created RoleArn instead of guessing a fixed wait.
    deadline = time.monotonic() + timeout_s
    last: Exception | dict[str, Any] | None = None
    while time.monotonic() < deadline:
        resp = events.put_targets(Rule=rule, Targets=targets)
        if resp.get("FailedEntryCount", 0) == 0:
            return
        last = resp
        time.sleep(3)
    raise AssertionError(f"put_targets never succeeded for rule {rule}: {last}")


def _message_arrives(ctx, queue_url: str, key: str, value: str, timeout_s: float) -> bool:
    sqs = ctx.client("sqs")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        resp = sqs.receive_message(QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=5)
        for m in resp.get("Messages", []):
            body = json.loads(m["Body"])
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=m["ReceiptHandle"])
            if body.get(key) == value:
                return True
    return False


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
