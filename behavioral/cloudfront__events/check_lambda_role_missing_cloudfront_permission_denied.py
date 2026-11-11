"""lambda-role-missing-cloudfront-permission-denied."""
from __future__ import annotations

import io
import json
import time
import zipfile

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "lambda-role-missing-cloudfront-permission-denied"
GROUP = "permission-boundary"
SERVICES = ["cloudfront", "events"]

_CACHING_DISABLED_POLICY_ID = "4135ea2d-6df8-44a3-9df3-4b5a84be39ad"

_HANDLER_CODE_SAFE = '''
import os

import boto3
from botocore.exceptions import ClientError


def handler(event, context):
    detail = event.get("detail", {})
    key = detail.get("object", {}).get("key", "unknown")
    cf = boto3.client("cloudfront")
    try:
        resp = cf.create_invalidation(
            DistributionId=os.environ["DISTRIBUTION_ID"],
            InvalidationBatch={
                "Paths": {"Quantity": 1, "Items": ["/" + key]},
                "CallerReference": context.aws_request_id,
            },
        )
        return {"ok": True, "invalidationId": resp["Invalidation"]["Id"]}
    except ClientError as err:
        return {"ok": False, "code": err.response["Error"]["Code"]}
'''


@tags("axis:rejection", "cap:c3", "cap:c7", "concern:data-plane", "concern:e2e", "concern:eventing", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """A Lambda execution role lacking cloudfront:CreateInvalidation gets denied by CloudFront and creates
    no invalidation, even though EventBridge successfully invoked it; a role with the permission succeeds."""
    dist_id, _ = _create_cloudfront_distribution(ctx, "sim2real-rolebound-origin.s3.amazonaws.com")

    denied_role_arn = _create_lambda_role(ctx, allow_cloudfront=False)
    denied_fn = _create_lambda_function(ctx, denied_role_arn, _HANDLER_CODE_SAFE, env={"DISTRIBUTION_ID": dist_id})

    allowed_role_arn = _create_lambda_role(ctx, allow_cloudfront=True)
    allowed_fn = _create_lambda_function(ctx, allowed_role_arn, _HANDLER_CODE_SAFE, env={"DISTRIBUTION_ID": dist_id})

    events = ctx.client("events")
    lam = ctx.client("lambda")
    marker = ctx.unique_name("sim2real-marker-")

    denied_rule = ctx.unique_name("sim2real-cfevt-rule-denied-")
    denied_pattern = {
        "source": ["sim2real.roletest"],
        "detail-type": ["Denied"],
        "detail": {"bucket": {"name": [marker]}},
    }
    denied_rule_resp = events.put_rule(Name=denied_rule, EventPattern=json.dumps(denied_pattern), State="ENABLED")
    ctx.on_cleanup(lambda: events.delete_rule(Name=denied_rule))
    lam.add_permission(
        FunctionName=denied_fn["name"],
        StatementId="AllowEventBridgeInvoke",
        Action="lambda:InvokeFunction",
        Principal="events.amazonaws.com",
        SourceArn=denied_rule_resp["RuleArn"],
    )
    events.put_targets(Rule=denied_rule, Targets=[{"Id": "lambda-target", "Arn": denied_fn["arn"]}])
    ctx.on_cleanup(lambda: events.remove_targets(Rule=denied_rule, Ids=["lambda-target"]))

    allowed_rule = ctx.unique_name("sim2real-cfevt-rule-allowed-")
    allowed_pattern = {
        "source": ["sim2real.roletest"],
        "detail-type": ["Allowed"],
        "detail": {"bucket": {"name": [marker]}},
    }
    allowed_rule_resp = events.put_rule(Name=allowed_rule, EventPattern=json.dumps(allowed_pattern), State="ENABLED")
    ctx.on_cleanup(lambda: events.delete_rule(Name=allowed_rule))
    lam.add_permission(
        FunctionName=allowed_fn["name"],
        StatementId="AllowEventBridgeInvoke",
        Action="lambda:InvokeFunction",
        Principal="events.amazonaws.com",
        SourceArn=allowed_rule_resp["RuleArn"],
    )
    events.put_targets(Rule=allowed_rule, Targets=[{"Id": "lambda-target", "Arn": allowed_fn["arn"]}])
    ctx.on_cleanup(lambda: events.remove_targets(Rule=allowed_rule, Ids=["lambda-target"]))

    cf = ctx.client("cloudfront")

    # (a) exact denial code: invoke the under-privileged function directly and read its captured error.
    direct_payload = json.loads(
        lam.invoke(
            FunctionName=denied_fn["name"],
            Payload=json.dumps({"detail": {"object": {"key": "direct-invoke-key.txt"}}}).encode(),
        )["Payload"].read()
    )
    assert direct_payload["ok"] is False, f"expected the denied role's direct invoke to fail, got {direct_payload}"
    assert direct_payload["code"] == "AccessDenied", f"expected AccessDenied, got {direct_payload['code']}"

    # (b) the effect is absent when routed through the real EventBridge trigger.
    denied_key = "denied-key.txt"
    events.put_events(
        Entries=[
            {
                "Source": "sim2real.roletest",
                "DetailType": "Denied",
                "Detail": json.dumps({"bucket": {"name": marker}, "object": {"key": denied_key}}),
            }
        ]
    )
    denied_inv = _find_matching_invalidation(cf, dist_id, f"/{denied_key}", timeout_s=45.0, interval_s=5.0)
    assert denied_inv is None, "an invalidation was created despite the role lacking cloudfront:CreateInvalidation"

    # (c) positive control: identical wiring, role with the permission, succeeds.
    allowed_key = "allowed-key.txt"
    events.put_events(
        Entries=[
            {
                "Source": "sim2real.roletest",
                "DetailType": "Allowed",
                "Detail": json.dumps({"bucket": {"name": marker}, "object": {"key": allowed_key}}),
            }
        ]
    )
    allowed_inv = _find_matching_invalidation(cf, dist_id, f"/{allowed_key}", timeout_s=90.0, interval_s=5.0)
    assert allowed_inv is not None, "the role with cloudfront:CreateInvalidation failed to create an invalidation"


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
    role = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust))["Role"]
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
