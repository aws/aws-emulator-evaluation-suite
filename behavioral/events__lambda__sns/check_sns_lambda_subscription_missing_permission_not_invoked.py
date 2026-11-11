"""sns-lambda-subscription-missing-permission-not-invoked."""
from __future__ import annotations

import io
import json
import time
import zipfile
from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "sns-lambda-subscription-missing-permission-not-invoked"
GROUP = "permission-boundary"
SERVICES = ["events", "lambda", "sns"]

_HANDLER_CODE = """
import json

def handler(event, context):
    print("INVOKED_MARKER:" + json.dumps(event))
    return {"ok": True}
"""


@tags("axis:negative-delivery", "cap:c3", "concern:data-plane", "concern:e2e", "concern:eventing", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """One SNS publish invokes only the subscribed Lambda whose resource policy allows sns.amazonaws.com; the
    subscribed function without that grant is never invoked."""
    role_arn = _create_lambda_role(ctx, ctx.unique_name("sim2real-snslamneg-role-"))

    allowed_name = ctx.unique_name("sim2real-snslamneg-allow-")
    allowed_arn = _create_function(ctx, allowed_name, _HANDLER_CODE, role_arn)
    _cleanup_log_group(ctx, allowed_name)

    denied_name = ctx.unique_name("sim2real-snslamneg-deny-")
    denied_arn = _create_function(ctx, denied_name, _HANDLER_CODE, role_arn)
    _cleanup_log_group(ctx, denied_name)

    sns = ctx.client("sns")
    topic_arn = sns.create_topic(
        Name=ctx.unique_name("sim2real-snslamneg-topic-"),
        Tags=[{"Key": "sim2real:managed", "Value": "true"}, {"Key": "sim2real:prefix", "Value": "sim2real-snslamneg"}],
    )["TopicArn"]
    ctx.on_cleanup(lambda: sns.delete_topic(TopicArn=topic_arn))

    lam = ctx.client("lambda")
    # Only the "allowed" function gets the resource-based policy statement that
    # lets sns.amazonaws.com invoke it. The "denied" function is left untouched.
    lam.add_permission(
        FunctionName=allowed_name,
        StatementId="sns-invoke",
        Action="lambda:InvokeFunction",
        Principal="sns.amazonaws.com",
        SourceArn=topic_arn,
    )

    sub_allowed = sns.subscribe(TopicArn=topic_arn, Protocol="lambda", Endpoint=allowed_arn)["SubscriptionArn"]
    ctx.on_cleanup(lambda: sns.unsubscribe(SubscriptionArn=sub_allowed))
    sub_denied = sns.subscribe(TopicArn=topic_arn, Protocol="lambda", Endpoint=denied_arn)["SubscriptionArn"]
    ctx.on_cleanup(lambda: sns.unsubscribe(SubscriptionArn=sub_denied))

    marker = ctx.unique_name("sim2real-marker-")
    sns.publish(TopicArn=topic_arn, Subject="behavioral-check", Message=marker)

    # Positive control: the permitted function IS invoked with the message.
    allowed_message = _find_marker_in_logs(ctx, allowed_name, marker, timeout_s=90)
    assert allowed_message is not None, "positive control failed: permitted function was never invoked"
    assert marker in allowed_message, f"expected marker {marker!r} in invoked message, got {allowed_message!r}"

    # Negative: the function lacking the resource policy is never invoked, even
    # though it is subscribed to the exact same topic and the exact same publish.
    denied_message = _find_marker_in_logs(ctx, denied_name, marker, timeout_s=45, interval_s=5)
    assert denied_message is None, "function without SNS invoke permission was invoked anyway"


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
        Tags=[{"Key": "sim2real:managed", "Value": "true"}, {"Key": "sim2real:prefix", "Value": "sim2real-snslamneg"}],
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
