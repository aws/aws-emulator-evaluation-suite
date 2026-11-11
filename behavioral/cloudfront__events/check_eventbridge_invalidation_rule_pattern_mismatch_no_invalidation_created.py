"""eventbridge-invalidation-rule-pattern-mismatch-no-invalidation-created."""
from __future__ import annotations

import io
import json
import time
import zipfile

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "eventbridge-invalidation-rule-pattern-mismatch-no-invalidation-created"
GROUP = "event-propagation"
SERVICES = ["cloudfront", "events"]

_CACHING_DISABLED_POLICY_ID = "4135ea2d-6df8-44a3-9df3-4b5a84be39ad"

_HANDLER_CODE = '''
import os

import boto3


def handler(event, context):
    detail = event.get("detail", {})
    key = detail.get("object", {}).get("key", "unknown")
    cf = boto3.client("cloudfront")
    resp = cf.create_invalidation(
        DistributionId=os.environ["DISTRIBUTION_ID"],
        InvalidationBatch={
            "Paths": {"Quantity": 1, "Items": ["/" + key]},
            "CallerReference": context.aws_request_id,
        },
    )
    return {"invalidationId": resp["Invalidation"]["Id"]}
'''


@tags("axis:negative-delivery", "cap:c3", "concern:e2e", "concern:eventing", "dp:api", "plane:data")
def run(ctx) -> None:
    """An S3 object created outside the rule's key-prefix filter never matches, so the Lambda target is
    never invoked and no invalidation is created; an object inside the prefix triggers one normally."""
    bucket = _create_eventbridge_enabled_bucket(ctx)
    dist_id, _ = _create_cloudfront_distribution(ctx, f"{bucket}.s3.amazonaws.com")
    role_arn = _create_lambda_role(ctx)
    fn = _create_lambda_function(ctx, role_arn, _HANDLER_CODE, env={"DISTRIBUTION_ID": dist_id})

    events = ctx.client("events")
    rule_name = ctx.unique_name("sim2real-cfevt-rule-")
    watched_prefix = "watched/"
    pattern = {
        "source": ["aws.s3"],
        "detail-type": ["Object Created"],
        "detail": {
            "bucket": {"name": [bucket]},
            "object": {"key": [{"prefix": watched_prefix}]},
        },
    }
    rule = events.put_rule(Name=rule_name, EventPattern=json.dumps(pattern), State="ENABLED")
    ctx.on_cleanup(lambda: events.delete_rule(Name=rule_name))
    rule_arn = rule["RuleArn"]

    lam = ctx.client("lambda")
    lam.add_permission(
        FunctionName=fn["name"],
        StatementId="AllowEventBridgeInvoke",
        Action="lambda:InvokeFunction",
        Principal="events.amazonaws.com",
        SourceArn=rule_arn,
    )
    events.put_targets(Rule=rule_name, Targets=[{"Id": "lambda-target", "Arn": fn["arn"]}])
    ctx.on_cleanup(lambda: events.remove_targets(Rule=rule_name, Ids=["lambda-target"]))

    s3 = ctx.client("s3")
    cf = ctx.client("cloudfront")

    # Twin control in the same instant: both keys land together and a single poll loop watches
    # for both outcomes at once. This bounds "the mismatched key never gets an invalidation" by
    # exactly how long delivery took for the matched key on the SAME rule in THIS run, instead of
    # a guessed sleep that could be shorter than a correct-but-slower target's own latency.
    mismatched_key = "other/ignored.txt"
    matched_key = f"{watched_prefix}included.txt"
    s3.put_object(Bucket=bucket, Key=mismatched_key, Body=b"outside the watched prefix")
    s3.put_object(Bucket=bucket, Key=matched_key, Body=b"inside the watched prefix")

    matched_inv, mismatched_inv = _poll_for_twin(
        cf, dist_id, matched_path=f"/{matched_key}", mismatched_path=f"/{mismatched_key}", timeout_s=180.0, interval_s=5.0
    )
    assert mismatched_inv is None, (
        f"an invalidation ({mismatched_inv}) was created for {mismatched_key!r}, outside the rule's key-prefix filter"
    )
    assert matched_inv is not None, (
        f"no invalidation appeared for {matched_key!r} within 180s even though it matches the rule's key-prefix filter"
    )
    assert matched_inv["InvalidationBatch"]["Paths"]["Items"] == [f"/{matched_key}"], (
        f"expected invalidation paths ['/{matched_key}'], got "
        f"{matched_inv['InvalidationBatch']['Paths']['Items']!r}"
    )


def _zip_bytes(code: str, filename: str = "index.py") -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr(filename, code)
    return buf.getvalue()


def _create_lambda_role(ctx) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-cfevt-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    role = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust))["Role"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    basic_policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=basic_policy_arn)
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=basic_policy_arn))
    policy_name = "cf-invalidate"
    policy_doc = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Action": "cloudfront:CreateInvalidation", "Resource": "*"}],
    }
    iam.put_role_policy(RoleName=role_name, PolicyName=policy_name, PolicyDocument=json.dumps(policy_doc))
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name))
    return role["Arn"]


def _create_lambda_function(ctx, role_arn: str, code: str, env: dict | None = None, timeout: int = 30) -> dict:
    lam = ctx.client("lambda")
    name = ctx.unique_name("sim2real-cfevt-fn-")
    zip_bytes = _zip_bytes(code)
    resp = None
    last_err = None
    for _ in range(10):
        try:
            ctx.on_cleanup(lambda _n=name: _delete_lambda_log_group(ctx, _n))
            resp = lam.create_function(
                FunctionName=name,
                Runtime="python3.12",
                Role=role_arn,
                Handler="index.handler",
                Code={"ZipFile": zip_bytes},
                Timeout=timeout,
                Environment={"Variables": env or {}},
            )
            break
        except lam.exceptions.InvalidParameterValueException as err:
            last_err = err
            time.sleep(3)
    if resp is None:
        raise last_err
    ctx.on_cleanup(lambda: lam.delete_function(FunctionName=name))
    lam.get_waiter("function_active").wait(FunctionName=name, WaiterConfig={"Delay": 2, "MaxAttempts": 150})
    return {"name": name, "arn": resp["FunctionArn"]}


def _create_cloudfront_distribution(ctx, origin_domain: str) -> tuple[str, str]:
    cf = ctx.client("cloudfront")
    ref = ctx.unique_name("sim2real-cfevt-")
    config = {
        "CallerReference": ref,
        "Origins": {
            "Quantity": 1,
            "Items": [
                {
                    "Id": "origin1",
                    "DomainName": origin_domain,
                    "S3OriginConfig": {"OriginAccessIdentity": ""},
                }
            ],
        },
        "DefaultCacheBehavior": {
            "TargetOriginId": "origin1",
            "ViewerProtocolPolicy": "allow-all",
            "CachePolicyId": _CACHING_DISABLED_POLICY_ID,
        },
        "Comment": "sim2real behavioral check",
        "Enabled": True,
    }
    resp = cf.create_distribution(DistributionConfig=config)
    dist = resp["Distribution"]
    dist_id = dist["Id"]
    ctx.on_cleanup(lambda: _delete_cloudfront_distribution(ctx, dist_id))
    return dist_id, dist["ARN"]


def _delete_cloudfront_distribution(ctx, dist_id: str, timeout_s: float = 1200.0, interval_s: float = 15.0) -> None:
    cf = ctx.client("cloudfront")
    cfg = cf.get_distribution_config(Id=dist_id)
    etag = cfg["ETag"]
    dc = cfg["DistributionConfig"]
    if dc.get("Enabled"):
        dc["Enabled"] = False
        upd = cf.update_distribution(Id=dist_id, DistributionConfig=dc, IfMatch=etag)
        etag = upd["ETag"]
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        info = cf.get_distribution(Id=dist_id)
        if info["Distribution"]["Status"] == "Deployed":
            etag = info["ETag"]
            break
        time.sleep(interval_s)
    cf.delete_distribution(Id=dist_id, IfMatch=etag)


def _create_eventbridge_enabled_bucket(ctx) -> str:
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-cfevt-")
    # us-east-1 is the one region where CreateBucket rejects an explicit LocationConstraint.
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region})
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(ctx, bucket))
    s3.put_bucket_notification_configuration(
        Bucket=bucket, NotificationConfiguration={"EventBridgeConfiguration": {}}
    )
    return bucket


def _empty_and_delete_bucket(ctx, bucket: str) -> None:
    s3 = ctx.client("s3")
    resp = s3.list_objects_v2(Bucket=bucket)
    for obj in resp.get("Contents", []):
        s3.delete_object(Bucket=bucket, Key=obj["Key"])
    s3.delete_bucket(Bucket=bucket)


def _poll_for_twin(
    cf, dist_id: str, matched_path: str, mismatched_path: str, timeout_s: float = 180.0, interval_s: float = 5.0
):
    """Poll once for both outcomes: returns (matched_inv, mismatched_inv), where exactly one of the
    two is non-None. Stops the instant either path shows up, so the negative's window is exactly as
    long as the positive control on the same wiring actually took in this run."""
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        resp = cf.list_invalidations(DistributionId=dist_id, MaxItems="100")
        for item in resp.get("InvalidationList", {}).get("Items", []):
            inv = cf.get_invalidation(DistributionId=dist_id, Id=item["Id"])["Invalidation"]
            paths = inv["InvalidationBatch"]["Paths"]["Items"]
            if mismatched_path in paths:
                return None, inv
            if matched_path in paths:
                return inv, None
        time.sleep(interval_s)
    return None, None


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
