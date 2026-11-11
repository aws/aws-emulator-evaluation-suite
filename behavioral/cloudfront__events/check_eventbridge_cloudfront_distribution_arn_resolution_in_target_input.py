"""eventbridge-cloudfront-distribution-arn-resolution-in-target-input."""
from __future__ import annotations

import json
import time
import zipfile
import io
from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "eventbridge-cloudfront-distribution-arn-resolution-in-target-input"
GROUP = "arn-resolution"
SERVICES = ["cloudfront", "events"]


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "concern:eventing", "dp:api", "plane:data")
def run(ctx) -> None:
    """An EventBridge InputTransformer correctly extracts the CloudFront distribution id out of
    a CloudTrail-shaped 'AWS API Call via CloudTrail' event and resolves it into the full
    distribution ARN passed as the invoked Lambda's input."""
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]

    queue_url, queue_arn = _create_queue(ctx)
    role_arn = _create_role(
        ctx,
        "arnres-exec",
        "lambda.amazonaws.com",
        {
            "Version": "2012-10-17",
            "Statement": [
                {"Effect": "Allow", "Action": "sqs:SendMessage", "Resource": queue_arn},
                {
                    "Effect": "Allow",
                    "Action": ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"],
                    "Resource": "*",
                },
            ],
        },
    )
    code = f"""
import boto3, json
def lambda_handler(event, context):
    boto3.client("sqs").send_message(QueueUrl="{queue_url}", MessageBody=json.dumps(event))
"""
    fn_arn, fn_name = _create_lambda(ctx, role_arn, code)
    _warm_up_role(ctx, fn_name, queue_url)

    rule_name = ctx.unique_name("sim2real-cf-arnres-rule-")
    events = ctx.client("events")
    event_source = "sim2real.cloudfront.simulated-cloudtrail"
    events.put_rule(
        Name=rule_name,
        EventPattern=json.dumps(
            {
                "source": [event_source],
                "detail-type": ["AWS API Call via CloudTrail"],
                "detail": {"eventName": ["CreateInvalidation2020_05_31"]},
            }
        ),
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

    input_template = (
        '{"distributionArn": "arn:aws:cloudfront::' + account_id + ':distribution/<distId>", '
        '"correlationId": "<corrId>"}'
    )
    events.put_targets(
        Rule=rule_name,
        Targets=[
            {
                "Id": "t",
                "Arn": fn_arn,
                "InputTransformer": {
                    "InputPathsMap": {
                        "distId": "$.detail.requestParameters.distributionId",
                        "corrId": "$.detail.eventID",
                    },
                    "InputTemplate": input_template,
                },
            }
        ],
    )
    ctx.on_cleanup(lambda: events.remove_targets(Rule=rule_name, Ids=["t"]))

    distribution_id = "EDFDVBD6EXAMPLE"
    correlation_id = ctx.unique_name("evt-")
    ctrail_detail = {
        "eventVersion": "1.08",
        "eventSource": "cloudfront.amazonaws.com",
        "eventName": "CreateInvalidation2020_05_31",
        "awsRegion": "us-east-1",  # CloudFront is global; CloudTrail always records its calls in us-east-1
        "requestParameters": {"distributionId": distribution_id},
        "eventID": correlation_id,
        "eventType": "AwsApiCall",
    }
    put_resp = events.put_events(
        Entries=[
            {
                "Source": event_source,
                "DetailType": "AWS API Call via CloudTrail",
                "Detail": json.dumps(ctrail_detail),
            }
        ]
    )
    assert put_resp.get("FailedEntryCount", 0) == 0, f"put_events failed: {put_resp}"

    received = _wait_for_matching_message(ctx, queue_url, "correlationId", correlation_id, timeout_s=120)
    expected_arn = f"arn:aws:cloudfront::{account_id}:distribution/{distribution_id}"
    assert received["distributionArn"] == expected_arn, (
        f"expected InputTransformer to resolve {expected_arn!r}, got {received.get('distributionArn')!r}"
    )


def _create_queue(ctx) -> tuple[str, str]:
    sqs = ctx.client("sqs")
    url = sqs.create_queue(QueueName=ctx.unique_name("sim2real-cf-arnres-q-"))["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))
    arn = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]
    return url, arn


def _create_role(ctx, kind: str, trust_principal: str, policy_doc: dict[str, Any]) -> str:
    iam = ctx.client("iam")
    name = ctx.unique_name(f"sim2real-cf-{kind}-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": trust_principal}, "Action": "sts:AssumeRole"}],
    }
    resp = iam.create_role(RoleName=name, AssumeRolePolicyDocument=json.dumps(trust))
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=name))
    iam.put_role_policy(RoleName=name, PolicyName="inline", PolicyDocument=json.dumps(policy_doc))
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=name, PolicyName="inline"))
    return resp["Role"]["Arn"]


def _zip_code(code: str) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("lambda_function.py", code)
    return buf.getvalue()


def _create_lambda(ctx, role_arn: str, code: str) -> tuple[str, str]:
    lam = ctx.client("lambda")
    name = ctx.unique_name("sim2real-arnres-fn-")
    last_err = None
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


def _warm_up_role(ctx, fn_name: str, queue_url: str, timeout_s: float = 60) -> None:
    """IAM role permissions attached just before function creation can lag behind for a few
    seconds; invoke directly (retrying on the function's own error) until the role's
    sqs:SendMessage permission has propagated, then drain the warm-up message(s) so they
    don't contaminate the real assertion."""
    lam = ctx.client("lambda")
    sqs = ctx.client("sqs")
    deadline = time.monotonic() + timeout_s
    last_err = None
    while time.monotonic() < deadline:
        resp = lam.invoke(FunctionName=fn_name, Payload=b"{}", InvocationType="RequestResponse")
        if resp.get("FunctionError"):
            last_err = resp["Payload"].read()
            time.sleep(3)
            continue
        break
    else:
        raise AssertionError(f"lambda role permissions never propagated: {last_err}")
    drain_deadline = time.monotonic() + 10
    while time.monotonic() < drain_deadline:
        r = sqs.receive_message(QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=2)
        msgs = r.get("Messages", [])
        if not msgs:
            break
        for m in msgs:
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=m["ReceiptHandle"])


def _wait_for_matching_message(ctx, queue_url: str, key: str, value: str, timeout_s: float) -> dict[str, Any]:
    sqs = ctx.client("sqs")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        resp = sqs.receive_message(QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=5)
        for m in resp.get("Messages", []):
            body = json.loads(m["Body"])
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=m["ReceiptHandle"])
            if body.get(key) == value:
                return body
    raise AssertionError(f"no message with {key}={value} arrived within {timeout_s}s")


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
