"""eventbridge-target-role-scoped-to-wrong-distribution-denied."""

from __future__ import annotations

import json
import time
import uuid
import zipfile
import io
from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "eventbridge-target-role-scoped-to-wrong-distribution-denied"
GROUP = "overly-permissive"
SERVICES = ["cloudfront", "events"]


@tags(
    "axis:rejection",
    "cap:c3",
    "cap:c7",
    "concern:e2e",
    "concern:eventing",
    "concern:negative-classes",
    "dp:api",
    "plane:data",
)
def run(ctx) -> None:
    """A Lambda role allowing cloudfront:CreateInvalidation on one distribution ARN is denied when
    the EventBridge event it was invoked for names a *different* distribution, while the same
    role/Lambda still succeeds for the distribution it is scoped to."""
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]

    dist_allowed = _create_distribution(ctx, "allowed")
    dist_denied = _create_distribution(ctx, "denied")

    queue_url, queue_arn = _create_queue(ctx)

    allowed_arn = f"arn:aws:cloudfront::{account_id}:distribution/{dist_allowed['id']}"
    lambda_role_arn = _create_role(
        ctx,
        "scoped-exec",
        "lambda.amazonaws.com",
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": "cloudfront:CreateInvalidation",
                    "Resource": allowed_arn,
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
from botocore.exceptions import ClientError
def lambda_handler(event, context):
    detail = event.get("detail", {{}})
    cf = boto3.client("cloudfront")
    result = {{"requestId": detail.get("requestId")}}
    try:
        resp = cf.create_invalidation(
            DistributionId=detail["distributionId"],
            InvalidationBatch={{
                "Paths": {{"Quantity": 1, "Items": ["/x"]}},
                "CallerReference": detail["requestId"],
            }},
        )
        result["outcome"] = "success"
        result["invalidationId"] = resp["Invalidation"]["Id"]
    except ClientError as exc:
        result["outcome"] = "denied"
        result["code"] = exc.response["Error"]["Code"]
        result["message"] = exc.response["Error"].get("Message")
    boto3.client("sqs").send_message(QueueUrl="{queue_url}", MessageBody=json.dumps(result))
"""
    fn_arn, fn_name = _create_lambda(ctx, lambda_role_arn, code)

    rule_name = ctx.unique_name("sim2real-cf-scope-rule-")
    events = ctx.client("events")
    events.put_rule(
        Name=rule_name,
        EventPattern=json.dumps(
            {
                "source": ["sim2real.cloudfront.test2"],
                "detail-type": ["CloudFront Invalidation Request"],
            }
        ),
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
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

    request_id_allowed = ctx.unique_name("req-allowed-")
    request_id_denied = ctx.unique_name("req-denied-")

    def _publish() -> None:
        events.put_events(
            Entries=[
                {
                    "Source": "sim2real.cloudfront.test2",
                    "DetailType": "CloudFront Invalidation Request",
                    "Detail": json.dumps(
                        {
                            "distributionId": dist_allowed["id"],
                            "requestId": request_id_allowed,
                        }
                    ),
                },
                {
                    "Source": "sim2real.cloudfront.test2",
                    "DetailType": "CloudFront Invalidation Request",
                    "Detail": json.dumps(
                        {
                            "distributionId": dist_denied["id"],
                            "requestId": request_id_denied,
                        }
                    ),
                },
            ]
        )

    # A rule this freshly created can take a few seconds to start matching PutEvents on the bus --
    # an event published before it does is simply never delivered, with no error and no retry from
    # EventBridge's side. Bounded retry: re-publish (CreateInvalidation's CallerReference is the
    # requestId, so a repeat delivery is idempotent) until both requestIds are observed or the
    # deadline passes.
    wanted = {request_id_allowed, request_id_denied}
    messages: dict[str, Any] = {}
    deadline = time.monotonic() + 180
    while wanted - messages.keys() and time.monotonic() < deadline:
        _publish()
        messages.update(
            _drain_matching_messages(
                ctx, queue_url, "requestId", wanted - messages.keys(), timeout_s=30
            )
        )
    missing = wanted - messages.keys()
    assert not missing, (
        f"no message(s) arrived for requestId(s) {missing} after retrying put_events for 180s"
    )
    msg_allowed = messages[request_id_allowed]
    msg_denied = messages[request_id_denied]

    assert msg_allowed["outcome"] == "success", (
        f"expected the scoped role to succeed on its own distribution, got {msg_allowed}"
    )
    assert "invalidationId" in msg_allowed, (
        f"expected an invalidation id on success, got {msg_allowed}"
    )

    assert msg_denied["outcome"] == "denied", (
        f"expected the scoped role to be denied on the other distribution, got {msg_denied}"
    )
    assert msg_denied["code"] == "AccessDenied", (
        f"expected AccessDenied, got {msg_denied.get('code')}"
    )
    role_name = lambda_role_arn.rsplit("/", 1)[-1]
    expected_message = (
        f"User: arn:aws:sts::{account_id}:assumed-role/{role_name}/{fn_name} is not authorized "
        f"to perform: cloudfront:CreateInvalidation on resource: "
        f"arn:aws:cloudfront::{account_id}:distribution/{dist_denied['id']} because no "
        f"identity-based policy allows the cloudfront:CreateInvalidation action"
    )
    assert msg_denied.get("message") == expected_message, (
        f"expected message {expected_message!r}, got {msg_denied.get('message')!r}"
    )

    cf = ctx.client("cloudfront")
    items = cf.list_invalidations(DistributionId=dist_denied["id"])[
        "InvalidationList"
    ].get("Items", [])
    assert items == [], (
        "an invalidation was created on the distribution the role was denied for"
    )


# ===== helpers =====


def _create_queue(ctx) -> tuple[str, str]:
    sqs = ctx.client("sqs")
    url = sqs.create_queue(
        QueueName=ctx.unique_name("sim2real-cf-scope-q-"),
        tags={"sim2real:managed": "true"},
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
    resp = iam.create_role(
        RoleName=name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
    )
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=name))
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
    name = ctx.unique_name("sim2real-scoped-invalidation-fn-")
    last_err = None
    # Bounded retry for IAM role-propagation lag: a freshly created role/policy is not
    # always immediately assumable, and CreateFunction can reject it for up to ~30s.
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
                Tags={"sim2real:managed": "true"},
            )
            break
        except Exception as exc:  # noqa: BLE001
            last_err = exc
            time.sleep(3)
    else:
        raise last_err
    ctx.on_cleanup(lambda: lam.delete_function(FunctionName=name))
    lam.get_waiter("function_active_v2").wait(FunctionName=name, WaiterConfig={"Delay": 2, "MaxAttempts": 150})
    return resp["FunctionArn"], name


def _drain_matching_messages(
    ctx, queue_url: str, key: str, values: set[str], timeout_s: float
) -> dict[str, Any]:
    """Collects, for up to `timeout_s`, one message per `values` entry, keyed on `body[key]`.

    Returns what arrived, possibly fewer than `values`; the caller decides whether that is final.

    A single drain loop, not one call per value: two nearly-simultaneous Lambda invocations can
    land their SQS messages in the SAME receive_message batch, and a call scoped to only one
    value would delete-and-discard the other value's message before its own turn to look for it.
    """
    sqs = ctx.client("sqs")
    found: dict[str, Any] = {}
    deadline = time.monotonic() + timeout_s
    while len(found) < len(values) and time.monotonic() < deadline:
        resp = sqs.receive_message(
            QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=5
        )
        for m in resp.get("Messages", []):
            body = json.loads(m["Body"])
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=m["ReceiptHandle"])
            v = body.get(key)
            if v in values:
                found[v] = body
    return found


def _create_distribution(ctx, kind: str) -> dict[str, str]:
    cf = ctx.client("cloudfront")
    caller_ref = ctx.unique_name(f"sim2real-cf-{kind}-")
    domain = f"{uuid.uuid4().hex[:20]}.example.com"
    config = {
        "CallerReference": caller_ref,
        "Comment": f"sim2real-{kind}",
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
    resp = cf.create_distribution_with_tags(
        DistributionConfigWithTags={
            "DistributionConfig": config,
            "Tags": {"Items": [{"Key": "sim2real:managed", "Value": "true"}]},
        }
    )
    dist_id = resp["Distribution"]["Id"]
    dist_arn = resp["Distribution"]["ARN"]

    def _cleanup() -> None:
        _delete_distribution(ctx, dist_id)

    ctx.on_cleanup(_cleanup)
    return {"id": dist_id, "arn": dist_arn}


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
