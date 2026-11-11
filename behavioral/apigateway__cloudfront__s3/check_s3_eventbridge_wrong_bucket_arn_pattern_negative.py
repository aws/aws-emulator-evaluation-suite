"""s3-eventbridge-wrong-bucket-arn-pattern-negative."""
from __future__ import annotations

import io
import json
import time
import zipfile
from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "s3-eventbridge-wrong-bucket-arn-pattern-negative"
GROUP = "permission-boundary"
SERVICES = ["apigateway", "cloudfront", "s3"]

_MANAGED_TAGS = {"sim2real:managed": "true", "sim2real:prefix": "sim2real-cfic"}


@tags("axis:negative-delivery", "cap:c3", "concern:data-plane", "concern:e2e", "concern:eventing", "dp:api", "plane:data")
def run(ctx) -> None:
    """A rule whose pattern names a different bucket ARN in `resources` never matches the real bucket's Object
    Created events, so no invalidation appears; correcting the ARN on the same rule makes it appear."""
    bucket_name = _create_bucket_with_eventbridge(ctx)
    dist_id, dist_arn = _create_distribution(ctx, bucket_name)
    role_arn = _create_lambda_role(ctx, dist_arn)
    function_name, function_arn = _create_invalidation_lambda(ctx, role_arn, dist_id)

    # Deliberately break exactly one thing: scope the rule's pattern to a DIFFERENT bucket ARN.
    decoy_bucket_name = ctx.unique_name("sim2real-cfic-decoy-")
    wrong_pattern = {
        "source": ["aws.s3"],
        "detail-type": ["Object Created"],
        "resources": [f"arn:aws:s3:::{decoy_bucket_name}"],
    }
    rule_name, rule_arn = _create_rule(ctx, bucket_name, event_pattern=wrong_pattern)
    _wire_rule_target(ctx, rule_name, function_name, function_arn, grant_permission=True)

    s3 = ctx.client("s3")
    cf = ctx.client("cloudfront")
    key_mismatch = "wrong-arn/object.txt"
    s3.put_object(Bucket=bucket_name, Key=key_mismatch, Body=b"should-not-match")

    # Bounded wait to give EventBridge a fair chance to (wrongly) match the event anyway.
    deadline = time.monotonic() + 60.0
    while time.monotonic() < deadline:
        if _invalidation_for_path(cf, dist_id, f"/{key_mismatch}") is not None:
            raise AssertionError(
                "CloudFront invalidation was created despite the rule pattern being scoped "
                "to a different bucket ARN than the one the object was written to"
            )
        time.sleep(5)
    assert _invalidation_for_path(cf, dist_id, f"/{key_mismatch}") is None, (
        "a CloudFront invalidation appeared for the mismatched-ARN object after the bounded "
        "60s wait window, despite the rule's pattern being scoped to a different bucket ARN"
    )

    # Positive control: fix the pattern to the real bucket ARN and confirm delivery now works.
    events = ctx.client("events")
    correct_pattern = {
        "source": ["aws.s3"],
        "detail-type": ["Object Created"],
        "resources": [f"arn:aws:s3:::{bucket_name}"],
    }
    events.put_rule(Name=rule_name, EventPattern=json.dumps(correct_pattern), State="ENABLED")

    key_match = "correct-arn/object.txt"
    s3.put_object(Bucket=bucket_name, Key=key_match, Body=b"should-match")
    result = _wait_for_effect(
        lambda: _invalidation_for_path(cf, dist_id, f"/{key_match}"),
        lambda r: r is not None,
        timeout_s=120,
        interval_s=5,
        description="CloudFront invalidation created after correcting the pattern's bucket ARN",
    )
    assert result is not None, (
        "no CloudFront invalidation appeared after correcting the rule's pattern to the "
        "real bucket ARN, so the wiring itself (not just the pattern) may be broken"
    )
    assert result["Status"] in ("InProgress", "Completed"), (
        f"unexpected invalidation status {result['Status']!r} for the corrected-pattern invalidation"
    )
    assert f"/{key_match}" in result["InvalidationBatch"]["Paths"]["Items"], (
        f"invalidation batch paths {result['InvalidationBatch']['Paths']['Items']!r} "
        f"did not include /{key_match}"
    )


def _poll_until(
    probe, predicate, *, timeout_s=60.0, interval_s=1.0, description="condition"
):
    """Poll probe() until predicate(result) is truthy; return the final result (raises on timeout)."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(
        f"{description} not met within {timeout_s}s. Last result: {last!r}"
    )


def _wait_for_effect(
    probe, predicate, timeout_s=120.0, interval_s=2.0, description="effect"
):
    """Poll for an async cross-service effect (default 120s — Kinesis/DDB-stream ESMs can need
    60-120s for cold-start + first delivery; fast effects return as soon as the predicate holds)."""
    return _poll_until(
        probe,
        predicate,
        timeout_s=timeout_s,
        interval_s=interval_s,
        description=description,
    )


def _invalidation_for_path(cf, dist_id: str, path: str) -> dict[str, Any] | None:
    items = cf.list_invalidations(DistributionId=dist_id).get("InvalidationList", {}).get(
        "Items", []
    )
    for item in items:
        detail = cf.get_invalidation(DistributionId=dist_id, Id=item["Id"])["Invalidation"]
        if path in detail["InvalidationBatch"]["Paths"]["Items"]:
            return detail
    return None


def _create_bucket_with_eventbridge(ctx) -> str:
    s3 = ctx.client("s3")
    bucket_name = ctx.unique_name("sim2real-cfic-src-")
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket_name)
    else:
        s3.create_bucket(
            Bucket=bucket_name,
            CreateBucketConfiguration={"LocationConstraint": ctx.region},
        )
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(ctx, bucket_name))
    s3.put_bucket_tagging(
        Bucket=bucket_name,
        Tagging={"TagSet": [{"Key": k, "Value": v} for k, v in _MANAGED_TAGS.items()]},
    )
    s3.put_bucket_notification_configuration(
        Bucket=bucket_name,
        NotificationConfiguration={"EventBridgeConfiguration": {}},
    )
    return bucket_name


def _empty_and_delete_bucket(ctx, bucket_name: str) -> None:
    s3 = ctx.client("s3")
    resp = s3.list_objects_v2(Bucket=bucket_name)
    for obj in resp.get("Contents", []):
        s3.delete_object(Bucket=bucket_name, Key=obj["Key"])
    s3.delete_bucket(Bucket=bucket_name)


def _create_distribution(ctx, bucket_name: str) -> tuple[str, str]:
    cf = ctx.client("cloudfront")
    dist_config = {
        "CallerReference": ctx.unique_name("sim2real-cfic-dist-"),
        "Comment": "sim2real behavioral check",
        "Enabled": True,
        "Origins": {
            "Quantity": 1,
            "Items": [
                {
                    "Id": "s3origin",
                    "DomainName": f"{bucket_name}.s3.{ctx.region}.amazonaws.com",
                    "S3OriginConfig": {"OriginAccessIdentity": ""},
                }
            ],
        },
        "DefaultCacheBehavior": {
            "TargetOriginId": "s3origin",
            "ViewerProtocolPolicy": "allow-all",
            "TrustedSigners": {"Enabled": False, "Quantity": 0},
            "ForwardedValues": {
                "QueryString": False,
                "Cookies": {"Forward": "none"},
            },
            "MinTTL": 0,
        },
    }
    resp = cf.create_distribution(DistributionConfig=dist_config)
    dist = resp["Distribution"]
    dist_id = dist["Id"]
    dist_arn = dist["ARN"]
    ctx.on_cleanup(lambda: _teardown_distribution(ctx, dist_id))
    cf.tag_resource(
        Resource=dist_arn,
        Tags={"Items": [{"Key": k, "Value": v} for k, v in _MANAGED_TAGS.items()]},
    )
    return dist_id, dist_arn


def _teardown_distribution(ctx, dist_id: str) -> None:
    cf = ctx.client("cloudfront")
    cfg = cf.get_distribution_config(Id=dist_id)
    etag = cfg["ETag"]
    conf = cfg["DistributionConfig"]
    if conf.get("Enabled"):
        conf["Enabled"] = False
        cf.update_distribution(Id=dist_id, DistributionConfig=conf, IfMatch=etag)
    # DeleteDistribution requires Status == "Deployed"; this can take many minutes.
    _poll_until(
        lambda: cf.get_distribution(Id=dist_id)["Distribution"]["Status"],
        lambda s: s == "Deployed",
        timeout_s=1800,
        interval_s=20,
        description=f"distribution {dist_id} Deployed before delete",
    )
    etag = cf.get_distribution_config(Id=dist_id)["ETag"]
    cf.delete_distribution(Id=dist_id, IfMatch=etag)


def _create_lambda_role(ctx, dist_arn: str) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-cfic-role-")
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "lambda.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_policy),
        Tags=[{"Key": k, "Value": v} for k, v in _MANAGED_TAGS.items()],
    )
    role_arn = role["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))

    managed_policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=managed_policy_arn)
    ctx.on_cleanup(
        lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=managed_policy_arn)
    )

    inline_policy_name = "cloudfront-invalidate"
    inline_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": "cloudfront:CreateInvalidation",
                "Resource": dist_arn,
            }
        ],
    }
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName=inline_policy_name,
        PolicyDocument=json.dumps(inline_policy),
    )
    ctx.on_cleanup(
        lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=inline_policy_name)
    )
    return role_arn


def _create_invalidation_lambda(ctx, role_arn: str, dist_id: str) -> tuple[str, str]:
    lam = ctx.client("lambda")
    function_name = ctx.unique_name("sim2real-cfic-fn-")
    code_str = (
        "import boto3, os, time\n"
        "def handler(event, context):\n"
        "    dist_id = os.environ['DISTRIBUTION_ID']\n"
        "    key = event.get('detail', {}).get('object', {}).get('key')\n"
        "    if not key:\n"
        "        return {'skipped': True}\n"
        "    client = boto3.client('cloudfront')\n"
        "    client.create_invalidation(\n"
        "        DistributionId=dist_id,\n"
        "        InvalidationBatch={\n"
        "            'Paths': {'Quantity': 1, 'Items': ['/' + key]},\n"
        "            'CallerReference': str(time.time()),\n"
        "        },\n"
        "    )\n"
        "    return {'invalidated': key}\n"
    )
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("index.py", code_str)
    zip_bytes = buf.getvalue()

    deadline = time.monotonic() + 60.0
    resp = None
    last_err: Exception | None = None
    while time.monotonic() < deadline:
        try:
            ctx.on_cleanup(lambda _n=function_name: _delete_lambda_log_group(ctx, _n))
            resp = lam.create_function(
                FunctionName=function_name,
                Runtime="python3.12",
                Role=role_arn,
                Handler="index.handler",
                Code={"ZipFile": zip_bytes},
                Timeout=30,
                Environment={"Variables": {"DISTRIBUTION_ID": dist_id}},
                Tags=dict(_MANAGED_TAGS),
            )
            break
        except lam.exceptions.InvalidParameterValueException as exc:
            # IAM role/policy propagation lag — retry until the role is assumable.
            last_err = exc
            time.sleep(3)
    if resp is None:
        raise AssertionError(f"lambda create_function never succeeded: {last_err}")

    function_arn = resp["FunctionArn"]
    ctx.on_cleanup(lambda: lam.delete_function(FunctionName=function_name))
    _poll_until(
        lambda: lam.get_function_configuration(FunctionName=function_name)["State"],
        lambda s: s == "Active",
        timeout_s=60,
        interval_s=2,
        description=f"lambda {function_name} Active",
    )
    return function_name, function_arn


def _create_rule(
    ctx, bucket_name: str, event_pattern: dict[str, Any] | None = None
) -> tuple[str, str]:
    events = ctx.client("events")
    rule_name = ctx.unique_name("sim2real-cfic-rule-")
    pattern = event_pattern or {
        "source": ["aws.s3"],
        "detail-type": ["Object Created"],
        "detail": {"bucket": {"name": [bucket_name]}},
    }
    resp = events.put_rule(
        Name=rule_name,
        EventPattern=json.dumps(pattern),
        State="ENABLED",
        Tags=[{"Key": k, "Value": v} for k, v in _MANAGED_TAGS.items()],
    )
    rule_arn = resp["RuleArn"]
    ctx.on_cleanup(lambda: events.delete_rule(Name=rule_name))
    return rule_name, rule_arn


def _wire_rule_target(
    ctx,
    rule_name: str,
    function_name: str,
    function_arn: str,
    grant_permission: bool = True,
) -> None:
    events = ctx.client("events")
    lam = ctx.client("lambda")
    target_id = "invalidation-lambda"
    events.put_targets(Rule=rule_name, Targets=[{"Id": target_id, "Arn": function_arn}])
    ctx.on_cleanup(lambda: events.remove_targets(Rule=rule_name, Ids=[target_id]))
    if grant_permission:
        rule_arn = events.describe_rule(Name=rule_name)["Arn"]
        statement_id = "AllowEventBridgeInvoke"
        lam.add_permission(
            FunctionName=function_name,
            StatementId=statement_id,
            Action="lambda:InvokeFunction",
            Principal="events.amazonaws.com",
            SourceArn=rule_arn,
        )
        ctx.on_cleanup(
            lambda: lam.remove_permission(
                FunctionName=function_name, StatementId=statement_id
            )
        )


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
