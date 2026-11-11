"""rds-eventbridge-schedule-invokes-lambda-sdk-positive."""
from __future__ import annotations

import io
import json
import time
import zipfile
from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "rds-eventbridge-schedule-invokes-lambda-sdk-positive"
GROUP = "event-propagation"
SERVICES = ["lambda", "rds", "secretsmanager"]


# timing:real-time — schedule: 54 s https://docs.aws.amazon.com/eventbridge/latest/userguide/eb-create-rule-schedule.html
@tags("axis:happy-path", "cap:c3", "cap:c4", "cap:c5", "concern:data-plane", "concern:e2e", "concern:eventing", "dp:api", "plane:data", "timing:real-time")
def run(ctx) -> None:
    """A scheduled EventBridge rule invokes a Lambda that calls rds:DescribeDBEngineVersions and
    forwards the result to SQS; the message names engine 'postgres' and a postgres parameter
    group family."""
    events = ctx.client("events")
    lam = ctx.client("lambda")

    queue = _create_signal_queue(ctx)
    role_name, role_arn = _create_lambda_role(ctx, queue["arn"])
    function_name = ctx.unique_name("sim2real-rds-evfn-")
    function_arn = _create_function(ctx, function_name, role_arn, _FORWARDER_CODE, {"QUEUE_URL": queue["url"]})

    rule_name = ctx.unique_name("sim2real-rds-evrule-")
    rule_arn = events.put_rule(
        Name=rule_name,
        ScheduleExpression="rate(1 minute)",
        State="ENABLED",
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )["RuleArn"]
    ctx.on_cleanup(lambda: events.delete_rule(Name=rule_name))
    events.put_targets(Rule=rule_name, Targets=[{"Id": "notify-lambda", "Arn": function_arn}])
    ctx.on_cleanup(lambda: events.remove_targets(Rule=rule_name, Ids=["notify-lambda"]))
    lam.add_permission(
        FunctionName=function_name,
        StatementId="allow-eventbridge-invoke",
        Action="lambda:InvokeFunction",
        Principal="events.amazonaws.com",
        SourceArn=rule_arn,
    )

    messages = _poll_for_forwarded_messages(ctx, queue["url"], timeout_s=200.0)
    assert messages, "EventBridge schedule never invoked the Lambda (no message forwarded to SQS)"
    payload = messages[0]
    assert payload.get("engine") == "postgres", f"expected engine 'postgres', forwarder sent {payload!r}"
    assert isinstance(payload.get("family"), str) and payload["family"].startswith("postgres"), (
        f"expected a postgres DBParameterGroupFamily, forwarder sent {payload!r}"
    )


_FORWARDER_CODE = """
import json
import os
import boto3

_sqs = boto3.client("sqs")
_rds = boto3.client("rds")


def handler(event, context):
    versions = _rds.describe_db_engine_versions(Engine="postgres", DefaultOnly=True)["DBEngineVersions"]
    family = versions[0]["DBParameterGroupFamily"] if versions else ""
    body = {"engine": "postgres", "family": family}
    _sqs.send_message(QueueUrl=os.environ["QUEUE_URL"], MessageBody=json.dumps(body))
    return {"forwarded": True}
"""


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


def _poll_for_forwarded_messages(ctx, queue_url, timeout_s=150.0) -> list[dict[str, Any]]:
    """Poll the forwarder's SQS queue for any message the Lambda sent, proving EventBridge
    actually invoked it."""
    sqs = ctx.client("sqs")
    matched: list[dict[str, Any]] = []
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline and not matched:
        resp = sqs.receive_message(QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=10)
        for msg in resp.get("Messages", []):
            body = json.loads(msg["Body"])
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=msg["ReceiptHandle"])
            matched.append(body)
    return matched


def _create_signal_queue(ctx) -> dict[str, str]:
    sqs = ctx.client("sqs")
    url = sqs.create_queue(
        QueueName=ctx.unique_name("sim2real-rds-evq-"), tags={"sim2real-check": CHECK}
    )["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))
    arn = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]
    return {"url": url, "arn": arn}


def _zip_code(code_str: str) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("lambda_function.py", code_str)
    return buf.getvalue()


def _create_lambda_role(ctx, queue_arn: str) -> tuple[str, str]:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-lambdarole-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))

    policy_name = f"{role_name}-inline"
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName=policy_name,
        PolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {"Effect": "Allow", "Action": "sqs:SendMessage", "Resource": queue_arn},
                    # DescribeDBEngineVersions has no resource-level permissions, hence "*".
                    {"Effect": "Allow", "Action": "rds:DescribeDBEngineVersions", "Resource": "*"},
                ],
            }
        ),
    )
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name))

    basic_exec_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=basic_exec_arn)
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=basic_exec_arn))
    return role_name, role_arn


def _create_function(
    ctx, name: str, role_arn: str, code_str: str, env: dict[str, str] | None = None, timeout: int = 30
) -> str:
    lam = ctx.client("lambda")
    kwargs: dict[str, Any] = dict(
        FunctionName=name,
        Runtime="python3.12",
        Role=role_arn,
        Handler="lambda_function.handler",
        Code={"ZipFile": _zip_code(code_str)},
        Timeout=timeout,
        Publish=True,
        Tags={"sim2real-check": CHECK},
    )
    if env:
        kwargs["Environment"] = {"Variables": env}

    deadline = time.monotonic() + 60.0
    resp = None
    last_exc: Exception | None = None
    while time.monotonic() < deadline:
        try:
            ctx.on_cleanup(lambda _n=name: _delete_lambda_log_group(ctx, _n))
            resp = lam.create_function(**kwargs)
            break
        except lam.exceptions.InvalidParameterValueException as exc:
            last_exc = exc
            time.sleep(3.0)
    if resp is None:
        raise AssertionError(f"create_function never succeeded (role propagation?): {last_exc}")

    ctx.on_cleanup(lambda: lam.delete_function(FunctionName=name))
    _poll_until(
        lambda: lam.get_function_configuration(FunctionName=name).get("State"),
        lambda s: s == "Active",
        timeout_s=60.0,
        interval_s=2.0,
        description=f"function {name} Active",
    )
    return resp["FunctionArn"]


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
