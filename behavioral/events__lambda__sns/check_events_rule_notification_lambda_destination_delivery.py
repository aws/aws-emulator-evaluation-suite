"""events-rule-notification-lambda-destination-delivery."""
from __future__ import annotations

import io
import json
import time
import zipfile
from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "events-rule-notification-lambda-destination-delivery"
GROUP = "notification"
SERVICES = ["events", "lambda", "sns"]

_HANDLER_CODE = """
import json

def handler(event, context):
    print("INVOKED_MARKER:" + json.dumps(event))
    return {"ok": True}
"""


@tags("axis:negative-delivery", "cap:c3", "concern:data-plane", "concern:e2e", "concern:eventing", "dp:api", "plane:data")
def run(ctx) -> None:
    """An EventBridge rule targeting Lambda delivers a matching event; a non-matching event is not delivered."""
    role_arn = _create_lambda_role(ctx, ctx.unique_name("sim2real-ebl-role-"))
    function_name = ctx.unique_name("sim2real-ebl-fn-")
    function_arn = _create_function(ctx, function_name, _HANDLER_CODE, role_arn)
    _cleanup_log_group(ctx, function_name)

    events = ctx.client("events")
    lam = ctx.client("lambda")

    source_val = ctx.unique_name("sim2real.ebl.source.")
    matching_detail_type = "sim2real-match"
    rule_name = ctx.unique_name("sim2real-ebl-rule-")
    events.put_rule(
        Name=rule_name,
        EventPattern=json.dumps({"source": [source_val], "detail-type": [matching_detail_type]}),
        State="ENABLED",
    )
    ctx.on_cleanup(lambda: events.delete_rule(Name=rule_name))
    rule_arn = events.describe_rule(Name=rule_name)["Arn"]

    events.put_targets(Rule=rule_name, Targets=[{"Id": "lambda-target", "Arn": function_arn}])
    ctx.on_cleanup(lambda: events.remove_targets(Rule=rule_name, Ids=["lambda-target"]))

    lam.add_permission(
        FunctionName=function_name,
        StatementId="events-invoke",
        Action="lambda:InvokeFunction",
        Principal="events.amazonaws.com",
        SourceArn=rule_arn,
    )

    match_marker = ctx.unique_name("sim2real-match-marker-")
    events.put_events(
        Entries=[
            {
                "Source": source_val,
                "DetailType": matching_detail_type,
                "Detail": json.dumps({"marker": match_marker}),
            }
        ]
    )
    delivered = _find_marker_in_logs(ctx, function_name, match_marker, timeout_s=90)
    assert delivered is not None, "matching event was never delivered to the Lambda target"
    assert match_marker in delivered, f"expected marker {match_marker!r} in delivered log line {delivered!r}"

    # Same source, mismatched detail-type: the rule pattern requires an exact
    # detail-type match, so this event must NOT reach the Lambda target.
    mismatch_marker = ctx.unique_name("sim2real-mismatch-marker-")
    events.put_events(
        Entries=[
            {
                "Source": source_val,
                "DetailType": "sim2real-does-not-match",
                "Detail": json.dumps({"marker": mismatch_marker}),
            }
        ]
    )
    not_delivered = _find_marker_in_logs(ctx, function_name, mismatch_marker, timeout_s=45, interval_s=5)
    assert not_delivered is None, "non-matching event was delivered to the Lambda target"


_LAMBDA_ASSUME_ROLE_POLICY = json.dumps(
    {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "lambda.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
)

_BASIC_EXEC_POLICY_ARN = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"


def _zip_code(code: str) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("index.py", code)
    return buf.getvalue()


def _create_lambda_role(ctx, name: str, extra_policy: dict[str, Any] | None = None) -> str:
    iam = ctx.client("iam")
    role_arn = iam.create_role(
        RoleName=name,
        AssumeRolePolicyDocument=_LAMBDA_ASSUME_ROLE_POLICY,
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
    )["Role"]["Arn"]
    iam.attach_role_policy(RoleName=name, PolicyArn=_BASIC_EXEC_POLICY_ARN)
    if extra_policy:
        iam.put_role_policy(RoleName=name, PolicyName=f"{name}-inline", PolicyDocument=json.dumps(extra_policy))

    def _cleanup():
        try:
            iam.detach_role_policy(RoleName=name, PolicyArn=_BASIC_EXEC_POLICY_ARN)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise
        if extra_policy:
            try:
                iam.delete_role_policy(RoleName=name, PolicyName=f"{name}-inline")
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "NoSuchEntity":
                    raise
        try:
            iam.delete_role(RoleName=name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise

    ctx.on_cleanup(_cleanup)
    return role_arn


def _create_function(ctx, name: str, code: str, role_arn: str, timeout: int = 30) -> str:
    lam = ctx.client("lambda")
    last_exc = None
    resp = None
    for _ in range(15):
        try:
            resp = lam.create_function(
                FunctionName=name,
                Runtime="python3.12",
                Role=role_arn,
                Handler="index.handler",
                Code={"ZipFile": _zip_code(code)},
                Timeout=timeout,
                Publish=False,
                Tags={"sim2real:managed": "true"},
            )
            break
        except lam.exceptions.InvalidParameterValueException as exc:
            last_exc = exc
            time.sleep(2)
    if resp is None:
        raise AssertionError(f"lambda create_function never succeeded (role propagation?): {last_exc}")
    ctx.on_cleanup(lambda: lam.delete_function(FunctionName=name))
    _wait_active(ctx, name)
    return resp["FunctionArn"]


def _wait_active(ctx, name: str, timeout_s: float = 60.0) -> None:
    lam = ctx.client("lambda")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        cfg = lam.get_function_configuration(FunctionName=name)
        if cfg["State"] == "Active":
            return
        time.sleep(2)
    raise AssertionError(f"function {name} never became Active")


def _cleanup_log_group(ctx, function_name: str) -> None:
    def _fn():
        try:
            ctx.client("logs").delete_log_group(logGroupName=f"/aws/lambda/{function_name}")
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise

    ctx.on_cleanup(_fn)


def _find_marker_in_logs(ctx, function_name: str, marker: str, timeout_s: float = 90.0, interval_s: float = 5.0):
    logs = ctx.client("logs")
    log_group = f"/aws/lambda/{function_name}"
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            resp = logs.filter_log_events(logGroupName=log_group)
            for event in resp.get("events", []):
                if marker in event["message"]:
                    return event["message"]
        except logs.exceptions.ResourceNotFoundException:
            pass
        time.sleep(interval_s)
    return None


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
