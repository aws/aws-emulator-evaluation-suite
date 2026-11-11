"""eventbridge-scheduled-rule-triggers-cloudfront-invalidation-lambda."""
from __future__ import annotations

import io
import json
import textwrap
import time
import zipfile
from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "eventbridge-scheduled-rule-triggers-cloudfront-invalidation-lambda"
GROUP = "event-propagation"
SERVICES = ["cloudfront", "events"]


# timing:real-time — schedule: 35 s https://docs.aws.amazon.com/eventbridge/latest/userguide/eb-scheduled-rule-pattern.html
@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:e2e", "concern:eventing", "dp:api", "plane:data", "timing:real-time")
def run(ctx) -> None:
    """A scheduled EventBridge rule invokes a Lambda that calls
    cloudfront.create_invalidation, and the invalidation appears via
    cloudfront.list_invalidations."""
    caller_ref = ctx.unique_name("sim2real-cfevt-sched-")
    dist_id, dist_arn = _create_minimal_distribution(ctx, caller_ref)

    marker = ctx.unique_name("sim2real-invpath-")
    role_arn = _create_lambda_role(
        ctx,
        extra_statements=[
            {"Effect": "Allow", "Action": "cloudfront:CreateInvalidation", "Resource": dist_arn}
        ],
    )
    fn_name, fn_arn = _create_invalidation_lambda(ctx, role_arn, dist_id, marker)

    rule_name = ctx.unique_name("sim2real-cfevt-schedrule-")
    events = ctx.client("events")
    lam = ctx.client("lambda")
    rule_arn = events.put_rule(
        Name=rule_name,
        ScheduleExpression="rate(1 minute)",
        State="ENABLED",
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
    )["RuleArn"]
    ctx.on_cleanup(lambda: events.delete_rule(Name=rule_name))
    statement_id = ctx.unique_name("sim2real-cfevt-perm-")
    lam.add_permission(
        FunctionName=fn_name,
        StatementId=statement_id,
        Action="lambda:InvokeFunction",
        Principal="events.amazonaws.com",
        SourceArn=rule_arn,
    )
    events.put_targets(Rule=rule_name, Targets=[{"Id": "target1", "Arn": fn_arn}])
    ctx.on_cleanup(lambda: events.remove_targets(Rule=rule_name, Ids=["target1"]))

    cf = ctx.client("cloudfront")

    def _has_marker_invalidation() -> bool:
        resp = cf.list_invalidations(DistributionId=dist_id)
        for item in resp.get("InvalidationList", {}).get("Items", []):
            inv = cf.get_invalidation(DistributionId=dist_id, Id=item["Id"])["Invalidation"]
            if marker in inv["InvalidationBatch"]["Paths"]["Items"][0]:
                return True
        return False

    _poll_until(
        _has_marker_invalidation,
        lambda found: found,
        timeout_s=180.0,
        interval_s=10.0,
        description="scheduled-rule-triggered invalidation appearing in list_invalidations",
    )


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=1.0, description="condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


def _create_lambda_role(ctx, extra_statements: list[dict[str, Any]] | None) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-cfevt-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    statements = [
        {"Effect": "Allow", "Action": ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"], "Resource": "*"}
    ]
    if extra_statements:
        statements.extend(extra_statements)
    policy_name = ctx.unique_name("sim2real-cfevt-policy-")
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName=policy_name,
        PolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": statements}),
    )
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name))
    return role_arn


_INVALIDATION_LAMBDA_SOURCE = textwrap.dedent(
    """
    import os
    import boto3

    def handler(event, context):
        cf = boto3.client("cloudfront")
        cf.create_invalidation(
            DistributionId=os.environ["DISTRIBUTION_ID"],
            InvalidationBatch={
                "Paths": {"Quantity": 1, "Items": [f"/{os.environ['MARKER']}/*"]},
                "CallerReference": context.aws_request_id,
            },
        )
        return {"ok": True}
    """
)


def _zip_lambda_code(source: str) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("index.py", source)
    return buf.getvalue()


def _create_invalidation_lambda(ctx, role_arn: str, dist_id: str, marker: str) -> tuple[str, str]:
    lam = ctx.client("lambda")
    fn_name = ctx.unique_name("sim2real-cfevt-inv-")
    code = _zip_lambda_code(_INVALIDATION_LAMBDA_SOURCE)
    last_err = None
    fn_arn = None
    for _ in range(8):
        try:
            ctx.on_cleanup(lambda _n=fn_name: _delete_lambda_log_group(ctx, _n))
            resp = lam.create_function(
                FunctionName=fn_name,
                Runtime="python3.12",
                Role=role_arn,
                Handler="index.handler",
                Code={"ZipFile": code},
                Timeout=30,
                Environment={"Variables": {"DISTRIBUTION_ID": dist_id, "MARKER": marker}},
                Tags={"sim2real:managed": "true"},
            )
            fn_arn = resp["FunctionArn"]
            break
        except lam.exceptions.InvalidParameterValueException as exc:
            # bounded retry covers IAM role -> Lambda assume-role propagation lag
            last_err = exc
            time.sleep(5)
    else:
        raise last_err
    ctx.on_cleanup(lambda: lam.delete_function(FunctionName=fn_name))
    _poll_until(
        lambda: lam.get_function_configuration(FunctionName=fn_name)["State"],
        lambda s: s == "Active",
        timeout_s=60,
        interval_s=2.0,
        description=f"lambda {fn_name} Active",
    )
    return fn_name, fn_arn


def _minimal_distribution_config(caller_reference: str) -> dict[str, Any]:
    return {
        "CallerReference": caller_reference,
        "Comment": "sim2real behavioral check",
        "Enabled": True,
        "Origins": {
            "Quantity": 1,
            "Items": [
                {
                    "Id": "origin1",
                    "DomainName": f"{caller_reference}.s3.amazonaws.com",
                    "S3OriginConfig": {"OriginAccessIdentity": ""},
                }
            ],
        },
        "DefaultCacheBehavior": {
            "TargetOriginId": "origin1",
            "ViewerProtocolPolicy": "allow-all",
            "TrustedSigners": {"Enabled": False, "Quantity": 0},
            "ForwardedValues": {"QueryString": False, "Cookies": {"Forward": "none"}},
            "MinTTL": 0,
        },
    }


def _create_minimal_distribution(ctx, caller_reference: str) -> tuple[str, str]:
    cf = ctx.client("cloudfront")
    resp = cf.create_distribution_with_tags(
        DistributionConfigWithTags={
            "DistributionConfig": _minimal_distribution_config(caller_reference),
            "Tags": {"Items": [{"Key": "sim2real:managed", "Value": "true"}]},
        }
    )
    dist = resp["Distribution"]
    ctx.on_cleanup(lambda: _delete_distribution_safe(ctx, dist["Id"]))
    return dist["Id"], dist["ARN"]


def _delete_distribution(ctx, dist_id: str) -> None:
    cf = ctx.client("cloudfront")
    cfg = cf.get_distribution_config(Id=dist_id)
    etag = cfg["ETag"]
    dist_config = cfg["DistributionConfig"]
    if dist_config.get("Enabled"):
        dist_config["Enabled"] = False
        cf.update_distribution(Id=dist_id, DistributionConfig=dist_config, IfMatch=etag)
    _poll_until(
        lambda: cf.get_distribution(Id=dist_id)["Distribution"]["Status"],
        lambda s: s == "Deployed",
        timeout_s=1800,
        interval_s=20.0,
        description=f"distribution {dist_id} Deployed after disable",
    )
    etag = cf.get_distribution(Id=dist_id)["ETag"]
    cf.delete_distribution(Id=dist_id, IfMatch=etag)


def _delete_distribution_safe(ctx, dist_id: str) -> None:
    try:
        _delete_distribution(ctx, dist_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in (
            "EntityNotFound",
            "NoSuchCachePolicy",
            "NoSuchContinuousDeploymentPolicy",
            "NoSuchDistribution",
            "NoSuchFieldLevelEncryptionConfig",
            "NoSuchOrigin",
            "NoSuchOriginRequestPolicy",
            "NoSuchRealtimeLogConfig",
            "NoSuchResponseHeadersPolicy",
            "TrustedKeyGroupDoesNotExist",
            "TrustedSignerDoesNotExist",
        ):
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
