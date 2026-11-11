"""eventbridge-target-missing-cloudfront-invalidation-permission-not-invoked."""
from __future__ import annotations

import io
import json
import textwrap
import time
import zipfile
from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "eventbridge-target-missing-cloudfront-invalidation-permission-not-invoked"
GROUP = "overly-permissive"
SERVICES = ["cloudfront", "events"]


@tags("axis:rejection", "cap:c3", "cap:c7", "concern:data-plane", "concern:eventing", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """Of two Lambdas invoked by one rule, the one whose role lacks cloudfront:CreateInvalidation gets AccessDenied
    and creates no invalidation while the other creates one; once the permission is granted, the same call from the
    first Lambda succeeds and its invalidation is listed."""
    caller_ref = ctx.unique_name("sim2real-cfevt-perm-")
    dist_id, dist_arn = _create_minimal_distribution(ctx, caller_ref)
    result_queue = _create_queue(ctx)

    control_role = _create_lambda_role(
        ctx, extra_statements=[{"Effect": "Allow", "Action": "cloudfront:CreateInvalidation", "Resource": dist_arn}]
    )
    negative_role = _create_lambda_role(ctx, extra_statements=None)

    control_fn, control_arn = _create_invalidation_attempt_lambda(
        ctx, control_role["arn"], dist_id, "controlmarker", result_queue["url"], "control"
    )
    negative_fn, negative_arn = _create_invalidation_attempt_lambda(
        ctx, negative_role["arn"], dist_id, "negativemarker", result_queue["url"], "negative"
    )

    events = ctx.client("events")
    lam = ctx.client("lambda")
    rule_name = ctx.unique_name("sim2real-cfevt-rule-")
    pattern = {"source": ["cfevt.synthetic"], "detail-type": ["InvalidationTrigger"]}
    rule_arn = events.put_rule(
        Name=rule_name, EventPattern=json.dumps(pattern), State="ENABLED",
        Tags=[{"Key": "sim2real:managed", "Value": "true"}, {"Key": "sim2real:check", "Value": CHECK}],
    )["RuleArn"]
    ctx.on_cleanup(lambda: events.delete_rule(Name=rule_name))
    for fn_name, fn_arn, target_id in [(control_fn, control_arn, "t-control"), (negative_fn, negative_arn, "t-negative")]:
        sid = ctx.unique_name("sim2real-cfevt-invperm-")
        lam.add_permission(
            FunctionName=fn_name, StatementId=sid, Action="lambda:InvokeFunction",
            Principal="events.amazonaws.com", SourceArn=rule_arn,
        )
    events.put_targets(
        Rule=rule_name,
        Targets=[{"Id": "t-control", "Arn": control_arn}, {"Id": "t-negative", "Arn": negative_arn}],
    )
    ctx.on_cleanup(lambda: events.remove_targets(Rule=rule_name, Ids=["t-control", "t-negative"]))

    event_entries = [{"Source": "cfevt.synthetic", "DetailType": "InvalidationTrigger", "Detail": "{}"}]
    results = _publish_and_await_results(
        ctx, events, event_entries, result_queue["url"], expected_roles={"control", "negative"},
        timeout_s=200.0, republish_after_s=40.0,
    )
    assert results["control"]["ok"] is True, results["control"]
    assert results["negative"]["ok"] is False, results["negative"]
    assert results["negative"]["error_code"] == "AccessDenied", results["negative"]

    cf = ctx.client("cloudfront")
    all_paths: list[str] = []
    for item in cf.list_invalidations(DistributionId=dist_id).get("InvalidationList", {}).get("Items", []):
        inv = cf.get_invalidation(DistributionId=dist_id, Id=item["Id"])["Invalidation"]
        all_paths.extend(inv["InvalidationBatch"]["Paths"]["Items"])
    assert any("controlmarker" in p for p in all_paths), all_paths
    assert not any("negativemarker" in p for p in all_paths), all_paths

    # Restore: grant the negative role the same permission the control role always had, then
    # demand the identical call (same role, same lambda code) now succeeds.
    iam = ctx.client("iam")
    iam.put_role_policy(
        RoleName=negative_role["name"],
        PolicyName=negative_role["policy_name"],
        PolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents", "sqs:SendMessage"],
                        "Resource": "*",
                    },
                    {"Effect": "Allow", "Action": "cloudfront:CreateInvalidation", "Resource": dist_arn},
                ],
            }
        ),
    )
    restored = _poll_until(
        lambda: _invoke_attempt_lambda(lam, negative_fn),
        lambda r: r.get("ok") is True or r.get("error_code") != "AccessDenied",
        timeout_s=60.0,
        interval_s=3.0,
        description="negative lambda's identical CreateInvalidation call succeeds once its role is granted the permission (IAM propagation)",
    )
    assert restored["ok"] is True, restored

    all_paths_after: list[str] = []
    for item in cf.list_invalidations(DistributionId=dist_id).get("InvalidationList", {}).get("Items", []):
        inv = cf.get_invalidation(DistributionId=dist_id, Id=item["Id"])["Invalidation"]
        all_paths_after.extend(inv["InvalidationBatch"]["Paths"]["Items"])
    assert any("negativemarker" in p for p in all_paths_after), all_paths_after


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=1.0, description="condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


def _create_queue(ctx) -> dict[str, str]:
    sqs = ctx.client("sqs")
    url = sqs.create_queue(
        QueueName=ctx.unique_name("sim2real-cfevt-q-"), tags={"sim2real": CHECK}
    )["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))
    arn = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]
    return {"url": url, "arn": arn}


def _invoke_attempt_lambda(lam, fn_name: str) -> dict[str, Any]:
    resp = lam.invoke(FunctionName=fn_name, InvocationType="RequestResponse", Payload=b"{}")
    payload = json.loads(resp["Payload"].read())
    if resp.get("FunctionError"):
        raise AssertionError(f"{fn_name} invoke raised: {payload}")
    return payload


def _publish_and_await_results(
    ctx, events, entries: list[dict[str, Any]], queue_url: str, expected_roles: set[str],
    *, timeout_s: float, republish_after_s: float,
) -> dict[str, Any]:
    """Publish, then drain the result queue; re-publish on a fixed cadence if nothing has arrived
    yet. A single EventBridge target invoke can silently miss its first attempt while the
    just-granted `lambda:InvokeFunction` resource policy is still propagating, and EventBridge's own
    retry backoff for that miss can run far longer than any wait budget a check can afford -- so this
    republishes client-side well before that backoff would, rather than trusting it."""
    sqs = ctx.client("sqs")
    out: dict[str, Any] = {}
    deadline = time.monotonic() + timeout_s
    next_publish = 0.0
    while time.monotonic() < deadline and set(out) != expected_roles:
        if time.monotonic() >= next_publish:
            resp = events.put_events(Entries=entries)
            assert resp.get("FailedEntryCount", 0) == 0, resp
            next_publish = time.monotonic() + republish_after_s
        resp = sqs.receive_message(QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=10)
        for msg in resp.get("Messages", []):
            body = json.loads(msg["Body"])
            out[body["role"]] = body
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=msg["ReceiptHandle"])
    if set(out) != expected_roles:
        raise AssertionError(
            f"expected results for {expected_roles}, got {set(out)} within {timeout_s}s "
            f"(republished every {republish_after_s}s)"
        )
    return out


def _create_lambda_role(ctx, extra_statements: list[dict[str, Any]] | None) -> dict[str, str]:
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
        Tags=[{"Key": "sim2real:managed", "Value": "true"}, {"Key": "sim2real:check", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    statements = [
        {
            "Effect": "Allow",
            "Action": ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents", "sqs:SendMessage"],
            "Resource": "*",
        }
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
    return {"arn": role_arn, "name": role_name, "policy_name": policy_name}


_ATTEMPT_SOURCE = textwrap.dedent(
    """
    import json
    import os
    import boto3
    import botocore

    def handler(event, context):
        cf = boto3.client("cloudfront")
        sqs = boto3.client("sqs")
        result = {"role": os.environ["ROLE_LABEL"]}
        try:
            cf.create_invalidation(
                DistributionId=os.environ["DISTRIBUTION_ID"],
                InvalidationBatch={
                    "Paths": {"Quantity": 1, "Items": [f"/{os.environ['MARKER']}/*"]},
                    "CallerReference": context.aws_request_id,
                },
            )
            result["ok"] = True
        except botocore.exceptions.ClientError as exc:
            result["ok"] = False
            result["error_code"] = exc.response["Error"]["Code"]
        sqs.send_message(QueueUrl=os.environ["RESULT_QUEUE_URL"], MessageBody=json.dumps(result))
        return result
    """
)


def _zip_lambda_code(source: str) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("index.py", source)
    return buf.getvalue()


def _create_invalidation_attempt_lambda(
    ctx, role_arn: str, dist_id: str, marker: str, result_queue_url: str, role_label: str
) -> tuple[str, str]:
    lam = ctx.client("lambda")
    fn_name = ctx.unique_name(f"sim2real-cfevt-{role_label}-")
    code = _zip_lambda_code(_ATTEMPT_SOURCE)
    last_err = None
    fn_arn = None
    # Bounded retry for IAM role propagation lag: a just-created role is not yet assumable by
    # Lambda, and CreateFunction reports that as InvalidParameterValueException.
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
                Environment={
                    "Variables": {
                        "DISTRIBUTION_ID": dist_id,
                        "MARKER": marker,
                        "RESULT_QUEUE_URL": result_queue_url,
                        "ROLE_LABEL": role_label,
                    }
                },
                Tags={"sim2real:managed": "true", "sim2real:check": CHECK},
            )
            fn_arn = resp["FunctionArn"]
            break
        except lam.exceptions.InvalidParameterValueException as exc:
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
            "Tags": {"Items": [{"Key": "sim2real:managed", "Value": "true"}, {"Key": "sim2real:check", "Value": CHECK}]},
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
