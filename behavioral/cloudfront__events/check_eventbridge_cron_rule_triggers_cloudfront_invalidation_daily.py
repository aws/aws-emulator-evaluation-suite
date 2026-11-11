"""eventbridge-cron-rule-triggers-cloudfront-invalidation-daily."""
from __future__ import annotations

import io
import json
import time
import zipfile
from datetime import datetime, timedelta, timezone
from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "eventbridge-cron-rule-triggers-cloudfront-invalidation-daily"
GROUP = "event-propagation"
SERVICES = ["cloudfront", "events"]

_LAMBDA_CODE = """
import os
import boto3

def handler(event, context):
    cf = boto3.client("cloudfront")
    cf.create_invalidation(
        DistributionId=os.environ["DISTRIBUTION_ID"],
        InvalidationBatch={
            "Paths": {"Quantity": 1, "Items": ["/cron-sched/*"]},
            "CallerReference": "cron-" + context.aws_request_id,
        },
    )
    return {"ok": True}
"""


# timing:real-time — schedule: 120 s https://docs.aws.amazon.com/eventbridge/latest/userguide/eb-scheduled-rule-pattern.html
@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:e2e", "concern:eventing", "dp:api", "plane:data", "timing:real-time")
def run(ctx) -> None:
    """A cron-scheduled EventBridge rule (the same field syntax used for a daily schedule)
    fires at its configured time and triggers the Lambda target's scheduled CloudFront cache
    invalidation."""
    dist = _create_minimal_distribution(ctx)

    exec_role = _create_role(
        ctx,
        "lambda.amazonaws.com",
        statements=[
            {"Effect": "Allow", "Action": ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"], "Resource": "*"},
            {"Effect": "Allow", "Action": "cloudfront:CreateInvalidation", "Resource": "*"},
        ],
        name_hint="exec",
    )
    fn = _create_lambda_function(ctx, exec_role["arn"], _LAMBDA_CODE, env={"DISTRIBUTION_ID": dist["id"]}, name_hint="fn")

    # Fire 1-2 minutes from now so the check stays bounded instead of waiting for a real
    # daily boundary; this exercises cron field parsing/matching distinctly from a rate()
    # schedule, using the exact "cron(Minutes Hours Day-of-month Month Day-of-week Year)"
    # syntax a real daily schedule uses.
    # The cron fires at the start of its minute, so the target is that minute's first instant.
    target = (datetime.now(timezone.utc) + timedelta(minutes=2)).replace(second=0, microsecond=0)
    schedule_expression = f"cron({target.minute} {target.hour} * * ? *)"

    events = ctx.client("events")
    rule_name = ctx.unique_name("sim2real-cronsched-rule-")
    rule_arn = events.put_rule(Name=rule_name, ScheduleExpression=schedule_expression, State="ENABLED")["RuleArn"]
    ctx.on_cleanup(lambda: _delete_rule(ctx, rule_name, ["1"]))
    events.tag_resource(ResourceARN=rule_arn, Tags=[{"Key": "sim2real-check", "Value": CHECK}])

    _add_lambda_invoke_permission(ctx, fn["name"], rule_name)
    _put_targets_with_retry(ctx, rule_name, [{"Id": "1", "Arn": fn["arn"]}])

    # Two-sided: a target fired more than EARLY_SLACK_S before its cron minute is not "the same
    # field syntax a real daily schedule uses" firing correctly -- it is some other mechanism
    # (an immediate invoke, a coarse rate()-style poll) that would pass this check for the wrong
    # reason. DEADLINE_SLACK_S bounds how long real cron dispatch + Lambda cold start + the
    # CloudFront control plane are allowed to lag behind the target minute.
    cf = ctx.client("cloudfront")
    early_slack_s = 20.0
    deadline = target + timedelta(seconds=150.0)
    while True:
        items = cf.list_invalidations(DistributionId=dist["id"]).get("InvalidationList", {}).get("Items", [])
        now = datetime.now(timezone.utc)
        if items:
            assert now >= target - timedelta(seconds=early_slack_s), (
                f"cron rule {schedule_expression} (target {target.isoformat()}) already shows an "
                f"invalidation at {now.isoformat()}, more than {early_slack_s}s early: {items!r} -- "
                f"a correct cron field match should not fire before its minute"
            )
            break
        assert now < deadline, (
            f"cron rule {schedule_expression} never triggered a CloudFront invalidation by "
            f"{deadline.isoformat()} (target was {target.isoformat()})"
        )
        time.sleep(10)


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


def _create_lambda_function(ctx, role_arn: str, code: str, env: dict[str, str] | None = None, name_hint: str = "fn") -> dict[str, str]:
    lam = ctx.client("lambda")
    name = ctx.unique_name(f"sim2real-{name_hint}-")
    zip_bytes = _zip_code(code)
    resp = None
    last_err = None
    for _ in range(20):
        try:
            ctx.on_cleanup(lambda _n=name: _delete_lambda_log_group(ctx, _n))
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
            time.sleep(3)
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
    resp = cf.create_distribution(DistributionConfig=config)
    dist_id = resp["Distribution"]["Id"]
    dist_arn = resp["Distribution"]["ARN"]
    ctx.on_cleanup(lambda: _delete_distribution(ctx, dist_id))
    cf.tag_resource(Resource=dist_arn, Tags={"Items": [{"Key": "sim2real-check", "Value": CHECK}]})
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
