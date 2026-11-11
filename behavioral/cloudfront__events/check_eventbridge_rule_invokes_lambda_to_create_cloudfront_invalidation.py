"""eventbridge-rule-invokes-lambda-to-create-cloudfront-invalidation."""
from __future__ import annotations

import io
import json
import time
import zipfile

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "eventbridge-rule-invokes-lambda-to-create-cloudfront-invalidation"
GROUP = "orchestration"
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


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "concern:e2e", "concern:eventing", "dp:api", "plane:data")
def run(ctx) -> None:
    """S3 PutObject -> EventBridge rule -> Lambda -> cloudfront.create_invalidation, visible via GetInvalidation."""
    bucket = _create_eventbridge_enabled_bucket(ctx)
    dist_id, _ = _create_cloudfront_distribution(ctx, f"{bucket}.s3.amazonaws.com")
    role_arn = _create_lambda_role(ctx, allow_cloudfront=True)
    fn = _create_lambda_function(ctx, role_arn, _HANDLER_CODE, env={"DISTRIBUTION_ID": dist_id})

    events = ctx.client("events")
    rule_name = ctx.unique_name("sim2real-cfevt-rule-")
    pattern = {
        "source": ["aws.s3"],
        "detail-type": ["Object Created"],
        "detail": {"bucket": {"name": [bucket]}},
    }
    rule = events.put_rule(
        Name=rule_name,
        EventPattern=json.dumps(pattern),
        State="ENABLED",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
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

    key = ctx.unique_name("orchestration-obj-") + ".txt"
    s3 = ctx.client("s3")
    cf = ctx.client("cloudfront")
    inv = _put_until_invalidated(s3, cf, bucket, dist_id, key, timeout_s=240.0)
    assert inv is not None, (
        f"no CloudFront invalidation with path /{key} appeared within 240s of repeated "
        f"S3 PutObject retries (S3's EventBridgeConfiguration is eventually consistent)"
    )
    assert inv["InvalidationBatch"]["Paths"]["Items"] == [f"/{key}"], (
        f"invalidation paths {inv['InvalidationBatch']['Paths']['Items']!r} do not match expected [/{key}]"
    )
    refetched = cf.get_invalidation(DistributionId=dist_id, Id=inv["Id"])["Invalidation"]
    assert refetched["Id"] == inv["Id"], f"GetInvalidation returned id {refetched['Id']!r}, expected {inv['Id']!r}"
    assert refetched["Status"] in ("InProgress", "Completed"), (
        f"unexpected invalidation status {refetched['Status']!r}, expected InProgress or Completed"
    )


def _zip_bytes(code: str, filename: str = "index.py") -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr(filename, code)
    return buf.getvalue()


def _create_lambda_role(ctx, allow_cloudfront: bool) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-cfevt-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    basic_policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=basic_policy_arn)
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=basic_policy_arn))
    if allow_cloudfront:
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
                Tags={"sim2real": CHECK},
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
    cf.tag_resource(Resource=dist["ARN"], Tags={"Items": [{"Key": "sim2real", "Value": CHECK}]})
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
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region})
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(ctx, bucket))
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [{"Key": "sim2real", "Value": CHECK}]})
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


def _find_matching_invalidation(cf, dist_id: str, path: str, timeout_s: float = 90.0, interval_s: float = 5.0):
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        resp = cf.list_invalidations(DistributionId=dist_id, MaxItems="100")
        for item in resp.get("InvalidationList", {}).get("Items", []):
            inv = cf.get_invalidation(DistributionId=dist_id, Id=item["Id"])["Invalidation"]
            if path in inv["InvalidationBatch"]["Paths"]["Items"]:
                return inv
        time.sleep(interval_s)
    return None


def _put_until_invalidated(s3, cf, bucket: str, dist_id: str, key: str, timeout_s: float = 240.0):
    """Re-put the same key until its S3->EventBridge notification triggers a CloudFront
    invalidation. Enabling EventBridgeConfiguration on a bucket is eventually consistent --
    AWS documents up to ~5 minutes before events start flowing -- so a single put right
    after enabling is racy; keep writing new versions of the object until one lands."""
    deadline = time.monotonic() + timeout_s
    attempt = 0
    while time.monotonic() < deadline:
        attempt += 1
        s3.put_object(Bucket=bucket, Key=key, Body=f"hello-cloudfront-invalidation-{attempt}".encode())
        remaining = deadline - time.monotonic()
        inv = _find_matching_invalidation(cf, dist_id, f"/{key}", timeout_s=min(20.0, max(remaining, 0.0)), interval_s=5.0)
        if inv is not None:
            return inv
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
