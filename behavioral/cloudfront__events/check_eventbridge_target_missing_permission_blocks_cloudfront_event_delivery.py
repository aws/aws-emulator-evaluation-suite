"""eventbridge-target-missing-permission-blocks-cloudfront-event-delivery."""
from __future__ import annotations

import io
import json
import time
import uuid
import zipfile
from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "eventbridge-target-missing-permission-blocks-cloudfront-event-delivery"
GROUP = "overly-permissive"
SERVICES = ["cloudfront", "events"]


@tags("axis:negative-delivery", "cap:c3", "cap:c7", "concern:data-plane", "concern:eventing", "dp:api", "plane:data")
def run(ctx) -> None:
    """A rule targeting a Lambda without a resource-based invoke permission for events.amazonaws.com delivers nothing
    for a CloudFront CreateDistribution event (the relay queue stays empty, depth 0); once the permission is granted,
    an equivalent event is delivered."""
    account_id = _account_id(ctx)
    queue = _create_queue(ctx)
    fn = _create_relay_lambda(ctx, queue["url"], queue["arn"])

    nonce_blocked = ctx.unique_name("cfperm-blocked-")
    nonce_ok = ctx.unique_name("cfperm-ok-")
    pattern = {
        "source": ["sim2real.cloudfront"],
        "detail-type": ["AWS API Call via CloudTrail"],
        "detail": {
            "eventName": ["CreateDistribution"],
            "requestParameters": {
                "distributionConfig": {"callerReference": [nonce_blocked, nonce_ok]}
            },
        },
    }
    rule = _put_rule(ctx, pattern)
    _put_lambda_target(ctx, rule["name"], fn["arn"])  # NOTE: no add_permission yet

    request_parameters_blocked = {
        "distributionConfig": {"callerReference": nonce_blocked, "enabled": True}
    }
    detail_blocked = _cloudfront_event_detail(
        "CreateDistribution", request_parameters_blocked, None, account_id
    )
    _put_event(ctx, "sim2real.cloudfront", detail_blocked)

    absence = _poll_for_absence(ctx, queue["url"], window_s=40, wait_s=5)
    assert absence == [], f"event delivered despite missing lambda invoke permission: {absence}"
    depth = ctx.client("sqs").get_queue_attributes(
        QueueUrl=queue["url"], AttributeNames=["ApproximateNumberOfMessages"]
    )["Attributes"]["ApproximateNumberOfMessages"]
    assert depth == "0", f"expected ApproximateNumberOfMessages=0 after absence window, got {depth!r}"

    _grant_events_invoke_lambda(ctx, fn["name"], rule["arn"])

    request_parameters_ok = {"distributionConfig": {"callerReference": nonce_ok, "enabled": True}}
    detail_ok = _cloudfront_event_detail(
        "CreateDistribution", request_parameters_ok, None, account_id
    )
    _put_event(ctx, "sim2real.cloudfront", detail_ok)

    delivered = _await_message_with_nonce(ctx, queue["url"], nonce_ok, timeout_s=90)
    assert (
        delivered["detail"]["requestParameters"]["distributionConfig"]["callerReference"]
        == nonce_ok
    ), f"positive-control delivery: expected callerReference={nonce_ok!r}, got {delivered!r}"


def _poll_until(
    probe, predicate, *, timeout_s=60.0, interval_s=1.0, description="condition"
):
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
    return _poll_until(
        probe,
        predicate,
        timeout_s=timeout_s,
        interval_s=interval_s,
        description=description,
    )


def _account_id(ctx) -> str:
    return ctx.client("sts").get_caller_identity()["Account"]


def _create_queue(ctx) -> dict[str, str]:
    sqs = ctx.client("sqs")
    url = sqs.create_queue(
        QueueName=ctx.unique_name("sim2real-cfevt-q-"), tags={"sim2real": CHECK}
    )["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))
    arn = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])["Attributes"][
        "QueueArn"
    ]
    return {"url": url, "arn": arn}


def _receive_all(ctx, queue_url, max_messages=10, wait_s=5) -> list[dict[str, Any]]:
    sqs = ctx.client("sqs")
    resp = sqs.receive_message(
        QueueUrl=queue_url, MaxNumberOfMessages=max_messages, WaitTimeSeconds=int(wait_s)
    )
    msgs = resp.get("Messages", [])
    for m in msgs:
        sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=m["ReceiptHandle"])
    return msgs


def _poll_for_absence(ctx, queue_url, window_s=40.0, wait_s=5) -> list[dict[str, Any]]:
    deadline = time.monotonic() + window_s
    seen: list[dict[str, Any]] = []
    while time.monotonic() < deadline:
        seen.extend(_receive_all(ctx, queue_url, max_messages=10, wait_s=wait_s))
        if seen:
            break
    return seen


def _await_message_with_nonce(ctx, queue_url, nonce, timeout_s=60.0, interval_s=5.0) -> dict[str, Any]:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        for m in _receive_all(ctx, queue_url, max_messages=10, wait_s=interval_s):
            body = json.loads(m["Body"])
            if (
                body.get("detail", {})
                .get("requestParameters", {})
                .get("distributionConfig", {})
                .get("callerReference")
                == nonce
            ):
                return body
    raise AssertionError(f"no relayed message with callerReference={nonce} within {timeout_s}s")


def _iam_role_for_lambda_sqs(ctx, queue_arn) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-cfevt-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "lambda.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    policy_doc = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"],
                "Resource": "*",
            },
            {"Effect": "Allow", "Action": "sqs:SendMessage", "Resource": queue_arn},
        ],
    }
    policy_name = ctx.unique_name("sim2real-cfevt-policy-")
    iam.put_role_policy(
        RoleName=role_name, PolicyName=policy_name, PolicyDocument=json.dumps(policy_doc)
    )
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name))
    return role_arn


def _create_relay_lambda(ctx, queue_url, queue_arn) -> dict[str, str]:
    lam = ctx.client("lambda")
    role_arn = _iam_role_for_lambda_sqs(ctx, queue_arn)
    code = (
        "import json, os, boto3\n"
        "sqs = boto3.client('sqs')\n"
        "def handler(event, context):\n"
        "    sqs.send_message(QueueUrl=os.environ['QUEUE_URL'], MessageBody=json.dumps(event))\n"
        "    return {'ok': True}\n"
    )
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("lambda_function.py", code)
    zip_bytes = buf.getvalue()
    func_name = ctx.unique_name("sim2real-cfevt-fn-")
    resp = None
    last_err: Exception | None = None
    for _ in range(10):
        try:
            ctx.on_cleanup(lambda _n=func_name: _delete_lambda_log_group(ctx, _n))
            resp = lam.create_function(
                FunctionName=func_name,
                Runtime="python3.12",
                Role=role_arn,
                Handler="lambda_function.handler",
                Code={"ZipFile": zip_bytes},
                Timeout=30,
                Environment={"Variables": {"QUEUE_URL": queue_url}},
                Tags={"sim2real": CHECK},
            )
            break
        except lam.exceptions.InvalidParameterValueException as exc:
            last_err = exc
            time.sleep(3)
    if resp is None:
        raise AssertionError(f"lambda create_function never succeeded: {last_err}")
    ctx.on_cleanup(lambda: lam.delete_function(FunctionName=func_name))
    _poll_until(
        lambda: lam.get_function(FunctionName=func_name)["Configuration"]["State"],
        lambda s: s == "Active",
        timeout_s=60,
        interval_s=2.0,
        description=f"lambda {func_name} Active",
    )
    return {"name": func_name, "arn": resp["FunctionArn"]}


def _put_rule(ctx, pattern, bus_name="default") -> dict[str, str]:
    events = ctx.client("events")
    rule_name = ctx.unique_name("sim2real-cfevt-rule-")
    events.put_rule(
        Name=rule_name,
        EventPattern=json.dumps(pattern),
        State="ENABLED",
        EventBusName=bus_name,
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: events.delete_rule(Name=rule_name, EventBusName=bus_name))
    rule_arn = events.describe_rule(Name=rule_name, EventBusName=bus_name)["Arn"]
    return {"name": rule_name, "arn": rule_arn}


def _put_lambda_target(ctx, rule_name, function_arn, bus_name="default") -> None:
    events = ctx.client("events")
    events.put_targets(
        Rule=rule_name, EventBusName=bus_name, Targets=[{"Id": "target-1", "Arn": function_arn}]
    )
    ctx.on_cleanup(
        lambda: events.remove_targets(Rule=rule_name, EventBusName=bus_name, Ids=["target-1"])
    )


def _grant_events_invoke_lambda(ctx, function_name, rule_arn) -> None:
    lam = ctx.client("lambda")
    statement_id = ctx.unique_name("sim2real-cfevt-perm-")
    lam.add_permission(
        FunctionName=function_name,
        StatementId=statement_id,
        Action="lambda:InvokeFunction",
        Principal="events.amazonaws.com",
        SourceArn=rule_arn,
    )
    ctx.on_cleanup(
        lambda: lam.remove_permission(FunctionName=function_name, StatementId=statement_id)
    )


def _cloudfront_event_detail(
    event_name, request_parameters, response_elements, account_id, recipient_account_id=None
) -> dict[str, Any]:
    now = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    return {
        "eventVersion": "1.08",
        "userIdentity": {
            "type": "IAMUser",
            "principalId": "AIDACKCEVSQ6C2EXAMPLE",
            "arn": f"arn:aws:iam::{account_id}:user/sim2real-behav",
            "accountId": account_id,
            "accessKeyId": "AKIAIOSFODNN7EXAMPLE",
            "userName": "sim2real-behav",
        },
        "eventTime": now,
        "eventSource": "cloudfront.amazonaws.com",
        "eventName": event_name,
        # CloudFront is a global service; real CloudTrail records its management events
        # with awsRegion "us-east-1" regardless of where the check itself runs.
        "awsRegion": "us-east-1",
        "sourceIPAddress": "203.0.113.10",
        "userAgent": "aws-cli/2.0",
        "requestParameters": request_parameters,
        "responseElements": response_elements,
        "requestID": str(uuid.uuid4()),
        "eventID": str(uuid.uuid4()),
        "readOnly": False,
        "eventType": "AwsApiCall",
        "managementEvent": True,
        "recipientAccountId": recipient_account_id or account_id,
        "eventCategory": "Management",
    }


def _put_event(ctx, source, detail, bus_name="default") -> None:
    events = ctx.client("events")
    resp = events.put_events(
        Entries=[
            {
                "Source": source,
                "DetailType": "AWS API Call via CloudTrail",
                "Detail": json.dumps(detail),
                "EventBusName": bus_name,
            }
        ]
    )
    assert resp["FailedEntryCount"] == 0, resp


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
