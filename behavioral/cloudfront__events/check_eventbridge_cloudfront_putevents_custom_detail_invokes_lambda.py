"""eventbridge-cloudfront-putevents-custom-detail-invokes-lambda."""

from __future__ import annotations

import json
import time
import uuid
import zipfile
import io
from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "eventbridge-cloudfront-putevents-custom-detail-invokes-lambda"
GROUP = "event-propagation"
SERVICES = ["cloudfront", "events"]


@tags(
    "axis:happy-path",
    "cap:c3",
    "concern:data-plane",
    "concern:e2e",
    "concern:eventing",
    "dp:api",
    "plane:data",
)
def run(ctx) -> None:
    """A custom PutEvents call with detail-type 'CloudFront Cache Purge Requested' matched by an
    EventBridge rule invokes a Lambda that performs a real cloudfront:CreateInvalidation with
    the exact paths carried in the event detail; a non-matching detail-type never invokes it."""
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]

    distribution = _create_distribution(ctx)
    queue_url, queue_arn = _create_queue(ctx)

    dist_arn = f"arn:aws:cloudfront::{account_id}:distribution/{distribution['id']}"
    role_arn = _create_role(
        ctx,
        "propagation-exec",
        "lambda.amazonaws.com",
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": "cloudfront:CreateInvalidation",
                    "Resource": dist_arn,
                },
                {"Effect": "Allow", "Action": "sqs:SendMessage", "Resource": queue_arn},
                {
                    "Effect": "Allow",
                    "Action": [
                        "logs:CreateLogGroup",
                        "logs:CreateLogStream",
                        "logs:PutLogEvents",
                    ],
                    "Resource": "*",
                },
            ],
        },
    )
    code = f"""
import boto3, json
def lambda_handler(event, context):
    detail = event.get("detail", {{}})
    cf = boto3.client("cloudfront")
    resp = cf.create_invalidation(
        DistributionId=detail["distributionId"],
        InvalidationBatch={{
            "Paths": {{"Quantity": len(detail["paths"]), "Items": detail["paths"]}},
            "CallerReference": detail["requestId"],
        }},
    )
    boto3.client("sqs").send_message(QueueUrl="{queue_url}", MessageBody=json.dumps({{
        "requestId": detail["requestId"],
        "invalidationId": resp["Invalidation"]["Id"],
        "paths": resp["Invalidation"]["InvalidationBatch"]["Paths"]["Items"],
    }}))
"""
    fn_arn, fn_name = _create_lambda(ctx, role_arn, code)

    rule_name = ctx.unique_name("sim2real-cf-propagation-rule-")
    events = ctx.client("events")
    events.put_rule(
        Name=rule_name,
        EventPattern=json.dumps(
            {
                "source": ["sim2real.cloudfront.purge"],
                "detail-type": ["CloudFront Cache Purge Requested"],
            }
        ),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: events.delete_rule(Name=rule_name))

    lam = ctx.client("lambda")
    lam.add_permission(
        FunctionName=fn_name,
        StatementId="allow-events",
        Action="lambda:InvokeFunction",
        Principal="events.amazonaws.com",
        SourceArn=f"arn:aws:events:{ctx.region}:{account_id}:rule/{rule_name}",
    )
    events.put_targets(Rule=rule_name, Targets=[{"Id": "t", "Arn": fn_arn}])
    ctx.on_cleanup(lambda: events.remove_targets(Rule=rule_name, Ids=["t"]))

    # Mismatch: wrong detail-type never reaches the target.
    mismatch_request_id = ctx.unique_name("mismatch-req-")
    events.put_events(
        Entries=[
            {
                "Source": "sim2real.cloudfront.purge",
                "DetailType": "Something Else Entirely",
                "Detail": json.dumps(
                    {
                        "distributionId": distribution["id"],
                        "paths": ["/mismatch/*"],
                        "requestId": mismatch_request_id,
                    }
                ),
            }
        ]
    )
    assert not _message_arrives(ctx, queue_url, mismatch_request_id, timeout_s=20), (
        "a non-matching detail-type event still invoked the target Lambda"
    )

    # Match: correct detail-type performs a real CreateInvalidation with the given paths.
    match_request_id = ctx.unique_name("match-req-")
    paths = ["/cache-purge-test/*"]
    events.put_events(
        Entries=[
            {
                "Source": "sim2real.cloudfront.purge",
                "DetailType": "CloudFront Cache Purge Requested",
                "Detail": json.dumps(
                    {
                        "distributionId": distribution["id"],
                        "paths": paths,
                        "requestId": match_request_id,
                    }
                ),
            }
        ]
    )
    msg = _wait_for_matching_message(ctx, queue_url, match_request_id, timeout_s=90)
    assert msg["paths"] == paths, (
        f"lambda reported paths {msg['paths']!r}, expected {paths!r}"
    )

    # Independent terminal read at the destination: confirm the invalidation the Lambda claims
    # to have created really exists in CloudFront, with the exact paths carried in the event.
    cf = ctx.client("cloudfront")
    ground_truth = cf.get_invalidation(
        DistributionId=distribution["id"], Id=msg["invalidationId"]
    )["Invalidation"]
    assert ground_truth["InvalidationBatch"]["Paths"]["Items"] == paths, (
        f"CloudFront's own record of invalidation {msg['invalidationId']} has paths "
        f"{ground_truth['InvalidationBatch']['Paths']['Items']!r}, expected {paths!r}"
    )


# ===== helpers =====


def _create_queue(ctx) -> tuple[str, str]:
    sqs = ctx.client("sqs")
    url = sqs.create_queue(
        QueueName=ctx.unique_name("sim2real-cf-propagation-q-"),
        tags={"sim2real": CHECK},
    )["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))
    arn = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])[
        "Attributes"
    ]["QueueArn"]
    return url, arn


def _create_role(
    ctx, kind: str, trust_principal: str, policy_doc: dict[str, Any]
) -> str:
    iam = ctx.client("iam")
    name = ctx.unique_name(f"sim2real-cf-{kind}-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": trust_principal},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    resp = iam.create_role(RoleName=name, AssumeRolePolicyDocument=json.dumps(trust))
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=name))
    iam.tag_role(RoleName=name, Tags=[{"Key": "sim2real", "Value": CHECK}])
    iam.put_role_policy(
        RoleName=name, PolicyName="inline", PolicyDocument=json.dumps(policy_doc)
    )
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=name, PolicyName="inline"))
    return resp["Role"]["Arn"]


def _zip_code(code: str) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("lambda_function.py", code)
    return buf.getvalue()


def _create_lambda(ctx, role_arn: str, code: str) -> tuple[str, str]:
    lam = ctx.client("lambda")
    name = ctx.unique_name("sim2real-propagation-fn-")
    last_err = None
    # A freshly-created IAM role is not always assumable by Lambda yet; retry create_function
    # (bounded, not an unconditional sleep) until the role has propagated.
    for _ in range(10):
        try:
            ctx.on_cleanup(lambda _n=name: _delete_lambda_log_group(ctx, _n))
            resp = lam.create_function(
                FunctionName=name,
                Runtime="python3.12",
                Role=role_arn,
                Handler="lambda_function.lambda_handler",
                Code={"ZipFile": _zip_code(code)},
                Timeout=30,
                Tags={"sim2real": CHECK},
            )
            break
        except lam.exceptions.InvalidParameterValueException as exc:
            last_err = exc
            time.sleep(3)
    else:
        raise last_err
    ctx.on_cleanup(lambda: lam.delete_function(FunctionName=name))
    lam.get_waiter("function_active_v2").wait(FunctionName=name, WaiterConfig={"Delay": 2, "MaxAttempts": 150})
    return resp["FunctionArn"], name


def _wait_for_matching_message(
    ctx, queue_url: str, request_id: str, timeout_s: float
) -> dict[str, Any]:
    sqs = ctx.client("sqs")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        resp = sqs.receive_message(
            QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=5
        )
        for m in resp.get("Messages", []):
            body = json.loads(m["Body"])
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=m["ReceiptHandle"])
            if body.get("requestId") == request_id:
                return body
    raise AssertionError(
        f"no message for requestId={request_id} arrived within {timeout_s}s"
    )


def _message_arrives(ctx, queue_url: str, request_id: str, timeout_s: float) -> bool:
    sqs = ctx.client("sqs")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        resp = sqs.receive_message(
            QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=5
        )
        for m in resp.get("Messages", []):
            body = json.loads(m["Body"])
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=m["ReceiptHandle"])
            if body.get("requestId") == request_id:
                return True
    return False


def _create_distribution(ctx) -> dict[str, str]:
    cf = ctx.client("cloudfront")
    caller_ref = ctx.unique_name("sim2real-cf-propagation-")
    domain = f"{uuid.uuid4().hex[:20]}.example.com"
    config = {
        "CallerReference": caller_ref,
        "Comment": "sim2real-propagation",
        "Enabled": True,
        "Origins": {
            "Quantity": 1,
            "Items": [
                {
                    "Id": "origin1",
                    "DomainName": domain,
                    "CustomOriginConfig": {
                        "HTTPPort": 80,
                        "HTTPSPort": 443,
                        "OriginProtocolPolicy": "http-only",
                    },
                }
            ],
        },
        "DefaultCacheBehavior": {
            "TargetOriginId": "origin1",
            "ViewerProtocolPolicy": "allow-all",
            "ForwardedValues": {"QueryString": False, "Cookies": {"Forward": "none"}},
            "MinTTL": 0,
            "TrustedSigners": {"Enabled": False, "Quantity": 0},
        },
    }
    resp = cf.create_distribution(DistributionConfig=config)
    dist_id = resp["Distribution"]["Id"]
    cf.tag_resource(
        Resource=resp["Distribution"]["ARN"],
        Tags={"Items": [{"Key": "sim2real", "Value": CHECK}]},
    )

    def _cleanup() -> None:
        _delete_distribution(ctx, dist_id)

    ctx.on_cleanup(_cleanup)
    return {"id": dist_id, "arn": resp["Distribution"]["ARN"]}


def _delete_distribution(ctx, dist_id: str) -> None:
    cf = ctx.client("cloudfront")
    deadline = time.monotonic() + 1800
    while time.monotonic() < deadline:
        got = cf.get_distribution(Id=dist_id)
        status = got["Distribution"]["Status"]
        etag = got["ETag"]
        if status == "Deployed":
            config = got["Distribution"]["DistributionConfig"]
            if config["Enabled"]:
                config["Enabled"] = False
                cf.update_distribution(
                    Id=dist_id, DistributionConfig=config, IfMatch=etag
                )
                time.sleep(2)
                continue
            cf.delete_distribution(Id=dist_id, IfMatch=etag)
            return
        time.sleep(2)
    raise AssertionError(
        f"distribution {dist_id} never reached Deployed status for cleanup"
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
