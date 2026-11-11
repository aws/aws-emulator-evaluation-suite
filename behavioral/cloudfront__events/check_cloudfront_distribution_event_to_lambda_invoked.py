"""cloudfront-distribution-event-to-lambda-invoked."""
from __future__ import annotations

import io
import json
import time
import zipfile
from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "cloudfront-distribution-event-to-lambda-invoked"
GROUP = "event-propagation"
SERVICES = ["cloudfront", "events"]

_HANDLER_CODE = """
import json

def handler(event, context):
    print("EVENT_MARKER:" + json.dumps(event))
    return {"ok": True}
"""


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "concern:e2e", "concern:eventing", "dp:api", "plane:data")
def run(ctx) -> None:
    """A CloudFront distribution state-change event matched by an EventBridge rule invokes
    a Lambda function target with the event payload intact."""
    role_arn = _create_lambda_role(ctx)
    fn = _create_lambda_function(ctx, role_arn, _HANDLER_CODE)

    rule = _create_rule(
        ctx,
        {
            "source": ["sim2real.cloudfront"],
            "detail-type": ["CloudFront Distribution State Change"],
            "detail": {"state": ["Deployed"]},
        },
    )
    _add_events_invoke_permission(ctx, fn["name"], rule["arn"], "allow-events-invoke")
    _put_target(ctx, rule["name"], "lambda-target", fn["arn"])

    marker = ctx.unique_name("dist-")
    events = ctx.client("events")
    events.put_events(
        Entries=[
            {
                "Source": "sim2real.cloudfront",
                "DetailType": "CloudFront Distribution State Change",
                "Detail": json.dumps(
                    {"distributionId": marker, "state": "Deployed", "eTag": "E3ABCXYZ"}
                ),
            }
        ]
    )

    message = _poll_logs_for_marker(ctx, fn["name"], marker, timeout_s=120.0)
    assert message is not None, "Lambda target was never invoked with the matching event"
    payload = json.loads(message.split("EVENT_MARKER:", 1)[1])
    assert payload["source"] == "sim2real.cloudfront", (
        f"expected source sim2real.cloudfront, got {payload.get('source')!r}"
    )
    assert payload["detail-type"] == "CloudFront Distribution State Change", (
        f"expected detail-type 'CloudFront Distribution State Change', got {payload.get('detail-type')!r}"
    )
    assert payload["detail"]["distributionId"] == marker, (
        f"expected detail.distributionId {marker!r}, got {payload['detail'].get('distributionId')!r}"
    )
    assert payload["detail"]["state"] == "Deployed", (
        f"expected detail.state 'Deployed', got {payload['detail'].get('state')!r}"
    )


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


def _create_rule(ctx, event_pattern: dict[str, Any]) -> dict[str, str]:
    events = ctx.client("events")
    rule_name = ctx.unique_name("sim2real-cfrule-")
    resp = events.put_rule(
        Name=rule_name, EventPattern=json.dumps(event_pattern), State="ENABLED"
    )
    ctx.on_cleanup(lambda: events.delete_rule(Name=rule_name))
    return {"name": rule_name, "arn": resp["RuleArn"]}


def _put_target(ctx, rule_name: str, target_id: str, target_arn: str) -> None:
    events = ctx.client("events")
    events.put_targets(Rule=rule_name, Targets=[{"Id": target_id, "Arn": target_arn}])
    ctx.on_cleanup(lambda: events.remove_targets(Rule=rule_name, Ids=[target_id]))


def _create_lambda_role(ctx) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-cflrole-")
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
        RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust)
    )["Role"]["Arn"]
    policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)

    def _cleanup():
        try:
            iam.detach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise
        iam.delete_role(RoleName=role_name)

    ctx.on_cleanup(_cleanup)
    return role_arn


def _create_lambda_function(ctx, role_arn: str, code: str) -> dict[str, str]:
    lam = ctx.client("lambda")
    fn_name = ctx.unique_name("sim2real-cflfn-")
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("lambda_function.py", code)
    zip_bytes = buf.getvalue()

    deadline = time.monotonic() + 90.0
    last_err: Exception | None = None
    resp = None
    while time.monotonic() < deadline:
        try:
            ctx.on_cleanup(lambda _n=fn_name: _delete_lambda_log_group(ctx, _n))
            resp = lam.create_function(
                FunctionName=fn_name,
                Runtime="python3.12",
                Role=role_arn,
                Handler="lambda_function.handler",
                Code={"ZipFile": zip_bytes},
                Timeout=30,
            )
            break
        except lam.exceptions.InvalidParameterValueException as e:
            last_err = e
            time.sleep(3.0)
    if resp is None:
        raise AssertionError(f"lambda creation never succeeded: {last_err}")

    ctx.on_cleanup(lambda: lam.delete_function(FunctionName=fn_name))
    _poll_until(
        lambda: lam.get_function(FunctionName=fn_name)["Configuration"]["State"],
        lambda s: s == "Active",
        timeout_s=60,
        interval_s=2.0,
        description="lambda Active",
    )
    return {"name": fn_name, "arn": resp["FunctionArn"]}


def _add_events_invoke_permission(
    ctx, function_name: str, rule_arn: str, statement_id: str
) -> None:
    lam = ctx.client("lambda")
    lam.add_permission(
        FunctionName=function_name,
        StatementId=statement_id,
        Action="lambda:InvokeFunction",
        Principal="events.amazonaws.com",
        SourceArn=rule_arn,
    )


def _poll_logs_for_marker(
    ctx, function_name: str, marker: str, timeout_s: float = 90.0
) -> str | None:
    logs = ctx.client("logs")
    log_group = f"/aws/lambda/{function_name}"
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            resp = logs.filter_log_events(logGroupName=log_group, limit=100)
            for event in resp.get("events", []):
                if marker in event["message"]:
                    return event["message"]
        except logs.exceptions.ResourceNotFoundException:
            pass
        time.sleep(3.0)
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
