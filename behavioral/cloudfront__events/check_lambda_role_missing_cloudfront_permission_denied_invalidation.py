"""lambda-role-missing-cloudfront-permission-denied-invalidation."""
from __future__ import annotations

import io
import json
import time
import zipfile
from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "lambda-role-missing-cloudfront-permission-denied-invalidation"
GROUP = "overly-permissive"
SERVICES = ["cloudfront", "events"]

_LAMBDA_CODE = """
import json
import os
import boto3
from botocore.exceptions import ClientError

def handler(event, context):
    cf = boto3.client("cloudfront")
    code = None
    try:
        cf.create_invalidation(
            DistributionId="E1234567890ABC",
            InvalidationBatch={
                "Paths": {"Quantity": 1, "Items": ["/*"]},
                "CallerReference": context.aws_request_id,
            },
        )
    except ClientError as exc:
        code = exc.response["Error"]["Code"]
    sqs = boto3.client("sqs")
    sqs.send_message(
        QueueUrl=os.environ["RESULTS_QUEUE_URL"],
        MessageBody=json.dumps({"fn": os.environ["FN_LABEL"], "error_code": code}),
    )
    return {"ok": True}
"""


@tags("axis:rejection", "cap:c3", "cap:c7", "concern:data-plane", "concern:e2e", "concern:eventing", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """Of two EventBridge-invoked Lambdas calling CreateInvalidation on a nonexistent distribution, the one whose role
    lacks cloudfront:CreateInvalidation gets AccessDenied, while the one whose role has it gets NoSuchDistribution:
    the refusal is the IAM boundary, not the distribution id."""
    results_queue = _create_queue(ctx, "results")

    denied_role = _create_role(
        ctx,
        "lambda.amazonaws.com",
        statements=[
            {"Effect": "Allow", "Action": ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"], "Resource": "*"},
            {"Effect": "Allow", "Action": "sqs:SendMessage", "Resource": results_queue["arn"]},
        ],
        name_hint="denied-role",
    )
    allowed_role = _create_role(
        ctx,
        "lambda.amazonaws.com",
        statements=[
            {"Effect": "Allow", "Action": ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"], "Resource": "*"},
            {"Effect": "Allow", "Action": "sqs:SendMessage", "Resource": results_queue["arn"]},
            {"Effect": "Allow", "Action": "cloudfront:CreateInvalidation", "Resource": "*"},
        ],
        name_hint="allowed-role",
    )

    denied_fn = _create_lambda_function(
        ctx, denied_role["arn"], _LAMBDA_CODE, env={"RESULTS_QUEUE_URL": results_queue["url"], "FN_LABEL": "denied"}, name_hint="denied-fn"
    )
    allowed_fn = _create_lambda_function(
        ctx, allowed_role["arn"], _LAMBDA_CODE, env={"RESULTS_QUEUE_URL": results_queue["url"], "FN_LABEL": "allowed"}, name_hint="allowed-fn"
    )

    events = ctx.client("events")
    rule_name = ctx.unique_name("sim2real-denyperm-rule-")
    pattern = {"source": ["sim2real.denyperm"], "detail-type": ["ping"]}
    events.put_rule(Name=rule_name, EventPattern=json.dumps(pattern), State="ENABLED")
    ctx.on_cleanup(lambda: _delete_rule(ctx, rule_name, ["denied", "allowed"]))

    _add_lambda_invoke_permission(ctx, denied_fn["name"], rule_name)
    _add_lambda_invoke_permission(ctx, allowed_fn["name"], rule_name)
    _put_targets_with_retry(
        ctx,
        rule_name,
        [{"Id": "denied", "Arn": denied_fn["arn"]}, {"Id": "allowed", "Arn": allowed_fn["arn"]}],
    )

    events.put_events(Entries=[{"Source": "sim2real.denyperm", "DetailType": "ping", "Detail": json.dumps({})}])

    messages = _drain_queue(ctx, results_queue["url"], expected_count=2, timeout_s=60.0)
    by_fn = {json.loads(m["Body"])["fn"]: json.loads(m["Body"])["error_code"] for m in messages}
    assert by_fn.get("denied") == "AccessDenied", f"expected AccessDenied for the denied role, got {by_fn.get('denied')!r}"
    assert by_fn.get("allowed") == "NoSuchDistribution", f"expected NoSuchDistribution for the allowed role, got {by_fn.get('allowed')!r}"


def _zip_code(code: str) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("index.py", code)
    return buf.getvalue()


def _create_role(ctx, principal: str, statements: list[dict[str, Any]] | None = None, name_hint: str = "role") -> dict[str, str]:
    iam = ctx.client("iam")
    name = ctx.unique_name(f"sim2real-{name_hint}-")
    trust = {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Principal": {"Service": principal}, "Action": "sts:AssumeRole"}]}
    arn = iam.create_role(RoleName=name, AssumeRolePolicyDocument=json.dumps(trust))["Role"]["Arn"]
    ctx.on_cleanup(lambda: _delete_role(ctx, name))
    if statements:
        iam.put_role_policy(RoleName=name, PolicyName="inline", PolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": statements}))
    return {"name": name, "arn": arn}


def _delete_role(ctx, name: str) -> None:
    iam = ctx.client("iam")
    try:
        for p in iam.list_role_policies(RoleName=name).get("PolicyNames", []):
            iam.delete_role_policy(RoleName=name, PolicyName=p)
        iam.delete_role(RoleName=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _create_lambda_function(ctx, role_arn: str, code: str, env: dict[str, str] | None = None, name_hint: str = "fn") -> dict[str, str]:
    lam = ctx.client("lambda")
    name = ctx.unique_name(f"sim2real-{name_hint}-")
    zip_bytes = _zip_code(code)
    # IAM propagation: retry CreateFunction's refusal of a role Lambda cannot assume yet.
    deadline = time.monotonic() + min(60.0, (ctx.time_left() or 60.0) - 5.0)
    while True:
        try:
            resp = lam.create_function(
                FunctionName=name,
                Runtime="python3.12",
                Role=role_arn,
                Handler="index.handler",
                Code={"ZipFile": zip_bytes},
                Timeout=30,
                Environment={"Variables": env or {}},
            )
            break
        except lam.exceptions.InvalidParameterValueException as exc:
            if "cannot be assumed by Lambda" not in str(exc) or time.monotonic() >= deadline:
                raise
            time.sleep(2)
    arn = resp["FunctionArn"]
    ctx.on_cleanup(lambda: lam.delete_function(FunctionName=name))
    _wait_lambda_active(ctx, name)
    return {"name": name, "arn": arn}


def _wait_lambda_active(ctx, name: str, timeout_s: float = 90.0) -> None:
    lam = ctx.client("lambda")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        cfg = lam.get_function_configuration(FunctionName=name)
        if cfg["State"] == "Active":
            return
        time.sleep(2)
    raise AssertionError(f"lambda function {name} did not become Active within {timeout_s}s")


def _add_lambda_invoke_permission(ctx, function_name: str, rule_name: str) -> None:
    lam = ctx.client("lambda")
    events = ctx.client("events")
    rule_arn = events.describe_rule(Name=rule_name)["Arn"]
    lam.add_permission(
        FunctionName=function_name,
        StatementId="allow-eventbridge",
        Action="lambda:InvokeFunction",
        Principal="events.amazonaws.com",
        SourceArn=rule_arn,
    )


def _create_queue(ctx, name_hint: str = "q") -> dict[str, str]:
    sqs = ctx.client("sqs")
    name = ctx.unique_name(f"sim2real-{name_hint}-")
    url = sqs.create_queue(QueueName=name)["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))
    arn = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]
    return {"url": url, "arn": arn}


def _drain_queue(ctx, queue_url: str, expected_count: int = 1, timeout_s: float = 60.0) -> list[dict[str, Any]]:
    sqs = ctx.client("sqs")
    out: list[dict[str, Any]] = []
    deadline = time.monotonic() + timeout_s
    while len(out) < expected_count and time.monotonic() < deadline:
        resp = sqs.receive_message(QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=5)
        for msg in resp.get("Messages", []):
            out.append(msg)
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=msg["ReceiptHandle"])
    if len(out) < expected_count:
        raise AssertionError(f"expected {expected_count} result messages, got {len(out)} within {timeout_s}s")
    return out


def _put_targets_with_retry(ctx, rule_name: str, targets: list[dict[str, Any]], timeout_s: float = 60.0) -> None:
    events = ctx.client("events")
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        resp = events.put_targets(Rule=rule_name, Targets=targets)
        if resp.get("FailedEntryCount", 0) == 0:
            return
        last = resp
        time.sleep(3)
    raise AssertionError(f"put_targets never succeeded for {rule_name}: {last}")


def _delete_rule(ctx, rule_name: str, target_ids: list[str]) -> None:
    events = ctx.client("events")
    try:
        events.remove_targets(Rule=rule_name, Ids=target_ids)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise
    try:
        events.delete_rule(Name=rule_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
