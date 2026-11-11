"""eventbridge-put-events-custom-detail-triggers-cloudfront-cache-invalidation."""
from __future__ import annotations

import io
import json
import time
import zipfile
from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "eventbridge-put-events-custom-detail-triggers-cloudfront-cache-invalidation"
GROUP = "event-propagation"
SERVICES = ["cloudfront", "events"]

_LAMBDA_CODE = """
import os
import boto3

def handler(event, context):
    cf = boto3.client("cloudfront")
    paths = event["detail"]["paths"]
    cf.create_invalidation(
        DistributionId=os.environ["DISTRIBUTION_ID"],
        InvalidationBatch={
            "Paths": {"Quantity": len(paths), "Items": paths},
            "CallerReference": "putevents-" + context.aws_request_id,
        },
    )
    return {"ok": True}
"""


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "concern:e2e", "concern:eventing", "dp:api", "plane:data")
def run(ctx) -> None:
    """A custom PutEvents call whose detail-type matches the rule's event pattern triggers the
    Lambda target chain and results in a real CloudFront invalidation, while an event with a
    mismatched detail-type is filtered out and creates no invalidation."""
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

    events = ctx.client("events")
    rule_name = ctx.unique_name("sim2real-putevents-rule-")
    pattern = {"source": ["sim2real.cache-purge"], "detail-type": ["cache-invalidation-requested"]}
    rule_arn = events.put_rule(Name=rule_name, EventPattern=json.dumps(pattern), State="ENABLED")["RuleArn"]
    events.tag_resource(ResourceARN=rule_arn, Tags=[{"Key": "sim2real:managed", "Value": "true"}])
    ctx.on_cleanup(lambda: _delete_rule(ctx, rule_name, ["1"]))

    _add_lambda_invoke_permission(ctx, fn["name"], rule_name)
    _put_targets_with_retry(ctx, rule_name, [{"Id": "1", "Arn": fn["arn"]}])

    cf = ctx.client("cloudfront")
    before = len(cf.list_invalidations(DistributionId=dist["id"]).get("InvalidationList", {}).get("Items", []))

    def _invalidations():
        return cf.list_invalidations(DistributionId=dist["id"]).get("InvalidationList", {}).get("Items", [])

    # Positive control: a matching event turns into a real invalidation. An event sent before the
    # new target and the role's grant propagate is dropped or fails, so it is resent every 10 s.
    last_sent = [0.0]

    def _send_match_and_list():
        if time.monotonic() - last_sent[0] >= 10.0:
            events.put_events(
                Entries=[{"Source": "sim2real.cache-purge", "DetailType": "cache-invalidation-requested", "Detail": json.dumps({"paths": ["/match/*"]})}]
            )
            last_sent[0] = time.monotonic()
        return _invalidations()

    items = _poll_until(_send_match_and_list, lambda items: len(items) > before, timeout_s=_cap(ctx, 90.0))
    assert items is not None and len(items) > before, "the matching PutEvents call never resulted in a CloudFront invalidation"
    seen = {inv["Id"] for inv in items}
    new_paths: dict[str, list[str]] = {}

    def _new_invalidation_paths():
        for inv in _invalidations():
            if inv["Id"] not in seen and inv["Id"] not in new_paths:
                batch = cf.get_invalidation(DistributionId=dist["id"], Id=inv["Id"])["Invalidation"]["InvalidationBatch"]
                new_paths[inv["Id"]] = batch["Paths"].get("Items", [])
        return [path for paths in new_paths.values() for path in paths]

    # Absence by contrast: the mismatched event, then a second matching one. Each invalidation
    # carries its event's paths, so once '/match-2/*' exists, no '/mismatch/*' means none was made.
    events.put_events(
        Entries=[{"Source": "sim2real.cache-purge", "DetailType": "unrelated-event", "Detail": json.dumps({"paths": ["/mismatch/*"]})}]
    )
    events.put_events(
        Entries=[{"Source": "sim2real.cache-purge", "DetailType": "cache-invalidation-requested", "Detail": json.dumps({"paths": ["/match-2/*"]})}]
    )
    paths = _poll_until(_new_invalidation_paths, lambda paths: "/match-2/*" in paths, timeout_s=_cap(ctx, 90.0))
    assert paths is not None and "/match-2/*" in paths, (
        "the second matching PutEvents call never resulted in a CloudFront invalidation"
    )
    assert "/mismatch/*" not in paths, (
        f"a mismatched detail-type still triggered a CloudFront invalidation: new invalidation "
        f"paths {paths!r}"
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
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
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
                Tags={"sim2real:managed": "true"},
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
    cf.tag_resource(Resource=dist_arn, Tags={"Items": [{"Key": "sim2real:managed", "Value": "true"}]})
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


def _cap(ctx, timeout_s: float) -> float:
    left = ctx.time_left()
    return timeout_s if left is None else min(timeout_s, left)


def _poll_until(probe, predicate, timeout_s: float = 60.0, interval_s: float = 2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    return last


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
