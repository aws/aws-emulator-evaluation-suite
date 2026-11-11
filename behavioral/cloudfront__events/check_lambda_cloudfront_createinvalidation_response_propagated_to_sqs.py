"""lambda-cloudfront-createinvalidation-response-propagated-to-sqs."""
from __future__ import annotations

import io
import json
import time
import zipfile
from datetime import datetime, timezone
from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "lambda-cloudfront-createinvalidation-response-propagated-to-sqs"
GROUP = "data-format"
SERVICES = ["cloudfront", "events"]

_INVALIDATOR_CODE = """
import json
import os
import boto3

def handler(event, context):
    cf = boto3.client("cloudfront")
    caller_ref = "dataformat-" + context.aws_request_id
    resp = cf.create_invalidation(
        DistributionId=os.environ["DISTRIBUTION_ID"],
        InvalidationBatch={
            "Paths": {"Quantity": 1, "Items": ["/data-format/*"]},
            "CallerReference": caller_ref,
        },
    )
    inv = resp["Invalidation"]
    events = boto3.client("events")
    events.put_events(Entries=[{
        "Source": "sim2real.invalidator",
        "DetailType": "invalidation-result",
        "Detail": json.dumps({
            "invalidation_id": inv["Id"],
            "status": inv["Status"],
            "create_time": inv["CreateTime"].isoformat(),
            "caller_reference": inv["InvalidationBatch"]["CallerReference"],
        }),
    }])
    return {"ok": True}
"""


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "concern:e2e", "concern:eventing", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """A real CreateInvalidation response's Id, Status, CreateTime and CallerReference survive a
    Lambda's PutEvents through a second rule into SQS without truncation, retyping or CreateTime
    drift, and the Id resolves to the same invalidation via GetInvalidation."""
    dist = _create_minimal_distribution(ctx)
    downstream = _create_queue(ctx, "downstream")

    exec_role = _create_role(
        ctx,
        "lambda.amazonaws.com",
        statements=[
            {"Effect": "Allow", "Action": ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"], "Resource": "*"},
            {"Effect": "Allow", "Action": "cloudfront:CreateInvalidation", "Resource": "*"},
            {"Effect": "Allow", "Action": "events:PutEvents", "Resource": "*"},
        ],
        name_hint="exec",
    )
    fn = _create_lambda_function(ctx, exec_role["arn"], _INVALIDATOR_CODE, env={"DISTRIBUTION_ID": dist["id"]}, name_hint="fn")

    events = ctx.client("events")

    trigger_rule = ctx.unique_name("sim2real-dfmt-trigger-")
    trigger_pattern = {"source": ["sim2real.dataformat-trigger"], "detail-type": ["invalidation-request"]}
    events.put_rule(
        Name=trigger_rule,
        EventPattern=json.dumps(trigger_pattern),
        State="ENABLED",
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: _delete_rule(ctx, trigger_rule, ["1"]))
    _add_lambda_invoke_permission(ctx, fn["name"], trigger_rule)
    _put_targets_with_retry(ctx, trigger_rule, [{"Id": "1", "Arn": fn["arn"]}])

    forward_rule = ctx.unique_name("sim2real-dfmt-forward-")
    forward_pattern = {"source": ["sim2real.invalidator"], "detail-type": ["invalidation-result"]}
    forward_rule_arn = events.put_rule(
        Name=forward_rule,
        EventPattern=json.dumps(forward_pattern),
        State="ENABLED",
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )["RuleArn"]
    ctx.on_cleanup(lambda: _delete_rule(ctx, forward_rule, ["1"]))
    _allow_events_to_send_sqs(ctx, downstream["url"], downstream["arn"], forward_rule_arn)
    _put_targets_with_retry(ctx, forward_rule, [{"Id": "1", "Arn": downstream["arn"]}])

    events.put_events(Entries=[{"Source": "sim2real.dataformat-trigger", "DetailType": "invalidation-request", "Detail": json.dumps({})}])

    # Two EventBridge hops plus a Lambda cold start and a real CreateInvalidation call can take
    # well over 90 s, so the drain waits up to 180 s for the message.
    messages = _drain_queue(ctx, downstream["url"], expected_count=1, timeout_s=180.0)
    received_at = datetime.now(timezone.utc)
    envelope = json.loads(messages[0]["Body"])
    detail = envelope["detail"]

    assert detail["invalidation_id"], "invalidation_id missing from propagated event"
    assert detail["status"] in ("InProgress", "Completed"), detail["status"]
    create_time = datetime.fromisoformat(detail["create_time"])
    if create_time.tzinfo is None:
        create_time = create_time.replace(tzinfo=timezone.utc)
    assert create_time <= received_at, "propagated create_time is in the future relative to receipt"
    assert detail["caller_reference"].startswith("dataformat-")

    cf = ctx.client("cloudfront")
    ground_truth = cf.get_invalidation(DistributionId=dist["id"], Id=detail["invalidation_id"])["Invalidation"]
    assert ground_truth["Id"] == detail["invalidation_id"]
    assert ground_truth["Status"] == detail["status"], (
        f"propagated status {detail['status']!r} does not match CloudFront's authoritative "
        f"status {ground_truth['Status']!r}"
    )
    assert ground_truth["InvalidationBatch"]["CallerReference"] == detail["caller_reference"]
    assert ground_truth["CreateTime"] == create_time, (
        f"propagated CreateTime {create_time!r} does not match CloudFront's authoritative "
        f"CreateTime {ground_truth['CreateTime']!r}"
    )


# ===== helpers =====


def _zip_code(code: str) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("index.py", code)
    return buf.getvalue()


def _create_role(ctx, principal: str, statements: list[dict[str, Any]] | None = None, name_hint: str = "role") -> dict[str, str]:
    iam = ctx.client("iam")
    name = ctx.unique_name(f"sim2real-{name_hint}-")
    trust = {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Principal": {"Service": principal}, "Action": "sts:AssumeRole"}]}
    arn = iam.create_role(
        RoleName=name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )["Role"]["Arn"]
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


def _cap(ctx, timeout_s: float) -> float:
    left = ctx.time_left()
    return timeout_s if left is None else min(timeout_s, left)


def _create_lambda_function(ctx, role_arn: str, code: str, env: dict[str, str] | None = None, name_hint: str = "fn") -> dict[str, str]:
    lam = ctx.client("lambda")
    name = ctx.unique_name(f"sim2real-{name_hint}-")
    zip_bytes = _zip_code(code)
    resp = None
    last_err = None
    # A just-created role is not yet assumable by Lambda (InvalidParameterValueException).
    deadline = time.monotonic() + _cap(ctx, 60.0)
    while time.monotonic() < deadline:
        try:
            resp = lam.create_function(
                FunctionName=name,
                Runtime="python3.12",
                Role=role_arn,
                Handler="index.handler",
                Code={"ZipFile": zip_bytes},
                Timeout=30,
                Environment={"Variables": env or {}},
                Tags={"sim2real-check": CHECK},
            )
            break
        except lam.exceptions.InvalidParameterValueException as exc:
            last_err = exc
            time.sleep(2)
    if resp is None:
        raise AssertionError(f"lambda create_function never succeeded (IAM role propagation?): {last_err}")
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
    url = sqs.create_queue(QueueName=name, tags={"sim2real-check": CHECK})["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))
    arn = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]
    return {"url": url, "arn": arn}


def _allow_events_to_send_sqs(ctx, queue_url: str, queue_arn: str, rule_arn: str) -> None:
    sqs = ctx.client("sqs")
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "AllowEventBridge",
                "Effect": "Allow",
                "Principal": {"Service": "events.amazonaws.com"},
                "Action": "sqs:SendMessage",
                "Resource": queue_arn,
                "Condition": {"ArnEquals": {"aws:SourceArn": rule_arn}},
            }
        ],
    }
    sqs.set_queue_attributes(QueueUrl=queue_url, Attributes={"Policy": json.dumps(policy)})


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
        raise AssertionError(f"expected {expected_count} downstream messages, got {len(out)} within {timeout_s}s")
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


def _create_minimal_distribution(ctx) -> dict[str, str]:
    cf = ctx.client("cloudfront")
    caller_ref = ctx.unique_name("sim2real-cf-")
    config = {
        "CallerReference": caller_ref,
        "Comment": caller_ref,
        "Enabled": False,
        "Origins": {
            "Quantity": 1,
            "Items": [
                {
                    "Id": "origin1",
                    "DomainName": "example.com",
                    "CustomOriginConfig": {
                        "HTTPPort": 80,
                        "HTTPSPort": 443,
                        "OriginProtocolPolicy": "https-only",
                        "OriginSslProtocols": {"Quantity": 1, "Items": ["TLSv1.2"]},
                    },
                }
            ],
        },
        "DefaultCacheBehavior": {
            "TargetOriginId": "origin1",
            "ViewerProtocolPolicy": "allow-all",
            "CachePolicyId": "4135ea2d-6df8-44a3-9df3-4b5a84be39ad",  # Managed-CachingDisabled
        },
    }
    resp = cf.create_distribution_with_tags(
        DistributionConfigWithTags={
            "DistributionConfig": config,
            "Tags": {"Items": [{"Key": "sim2real-check", "Value": CHECK}]},
        }
    )
    dist_id = resp["Distribution"]["Id"]
    dist_arn = resp["Distribution"]["ARN"]
    ctx.on_cleanup(lambda: _delete_distribution(ctx, dist_id))
    return {"id": dist_id, "arn": dist_arn}


def _delete_distribution(ctx, dist_id: str, timeout_s: float = 1500.0) -> None:
    cf = ctx.client("cloudfront")
    deadline = time.monotonic() + timeout_s
    status = None
    etag = None
    while time.monotonic() < deadline:
        got = cf.get_distribution(Id=dist_id)
        status = got["Distribution"]["Status"]
        etag = got["ETag"]
        if status == "Deployed":
            break
        time.sleep(15)
    if status != "Deployed":
        return
    try:
        cf.delete_distribution(Id=dist_id, IfMatch=etag)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchDistribution":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
