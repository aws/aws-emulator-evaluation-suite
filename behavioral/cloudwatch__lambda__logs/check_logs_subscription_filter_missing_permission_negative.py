"""logs-subscription-filter-missing-permission-negative."""
from __future__ import annotations

import io
import json
import time
import zipfile

from behavioral_harness import tags

CHECK = "logs-subscription-filter-missing-permission-negative"
GROUP = "permission-boundary"
SERVICES = ["cloudwatch", "lambda", "logs"]


@tags("axis:rejection", "cap:c3", "concern:data-plane", "concern:e2e", "concern:eventing", "concern:negative-classes", "dp:api", "plane:control", "plane:data")
def run(ctx) -> None:
    """PutSubscriptionFilter to a function that does not grant logs.amazonaws.com fails with the
    exact InvalidParameterException and creates no filter; after the grant the identical call
    succeeds and delivers a log line to the function."""
    lam = ctx.client("lambda")
    logs = ctx.client("logs")

    role_arn = _create_lambda_role(ctx)
    function_name = _create_marker_function(ctx, role_arn, _LAMBDA_CODE_LOGS)
    function_arn = lam.get_function(FunctionName=function_name)["Configuration"]["FunctionArn"]

    log_group_name = ctx.unique_name("sim2real-lgcwlam-lg-")
    logs.create_log_group(logGroupName=log_group_name, tags={"sim2real-check": CHECK})
    ctx.on_cleanup(lambda: logs.delete_log_group(logGroupName=log_group_name))

    # Deliberately break exactly one thing: no lambda.add_permission grant for
    # logs.amazonaws.com is added before creating the subscription filter.
    filter_name = ctx.unique_name("sim2real-subfilter-")
    try:
        logs.put_subscription_filter(
            logGroupName=log_group_name,
            filterName=filter_name,
            filterPattern="",
            destinationArn=function_arn,
        )
    except logs.exceptions.InvalidParameterException as exc:
        refusal = exc.response["Error"].get("Message")
    else:
        ctx.on_cleanup(
            lambda: logs.delete_subscription_filter(logGroupName=log_group_name, filterName=filter_name)
        )
        raise AssertionError(
            "expected PutSubscriptionFilter to be rejected without a logs.amazonaws.com "
            "invoke permission grant on the destination Lambda, but it succeeded"
        )
    expected = ("Could not execute the lambda function. Make sure you have given CloudWatch Logs "
                "permission to execute your function.")
    assert refusal == expected, f"PutSubscriptionFilter must say {expected!r}, got {refusal!r}"

    # Confirm no filter exists on the log group (the rejected call created nothing).
    existing = logs.describe_subscription_filters(logGroupName=log_group_name).get("subscriptionFilters", [])
    assert not existing, f"expected no subscription filters, found {existing!r}"

    # Positive control: grant the missing permission, then retry the identical
    # PutSubscriptionFilter call and confirm it now succeeds and delivers.
    log_group_arn = logs.describe_log_groups(logGroupNamePrefix=log_group_name)["logGroups"][0]["arn"]
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    stmt_id = ctx.unique_name("sim2real-permit-")
    lam.add_permission(
        FunctionName=function_name,
        StatementId=stmt_id,
        Action="lambda:InvokeFunction",
        Principal="logs.amazonaws.com",
        SourceArn=log_group_arn,
        SourceAccount=account_id,
    )

    def _try_put_filter():
        try:
            logs.put_subscription_filter(
                logGroupName=log_group_name,
                filterName=filter_name,
                filterPattern="",
                destinationArn=function_arn,
            )
            return True
        except logs.exceptions.InvalidParameterException:
            return False

    _poll_until(
        _try_put_filter,
        lambda ok: ok,
        timeout_s=60.0,
        interval_s=5.0,
        description="PutSubscriptionFilter succeeds once permission has propagated",
    )
    ctx.on_cleanup(
        lambda: logs.delete_subscription_filter(logGroupName=log_group_name, filterName=filter_name)
    )

    since_ms2 = int(time.time() * 1000)
    stream_name = ctx.unique_name("sim2real-stream-")
    logs.create_log_stream(logGroupName=log_group_name, logStreamName=stream_name)
    fixed_message = ctx.unique_name("sim2real-fixed-")
    logs.put_log_events(
        logGroupName=log_group_name,
        logStreamName=stream_name,
        logEvents=[{"timestamp": since_ms2, "message": fixed_message}],
    )
    messages = _wait_for_decoded_messages(ctx, function_name, since_ms2, fixed_message, timeout_s=120)
    assert any(fixed_message in m for m in messages), f"expected {fixed_message!r} in {messages!r}"


_LAMBDA_CODE_LOGS = """
import base64
import gzip
import json


def handler(event, context):
    data = event["awslogs"]["data"]
    payload = json.loads(gzip.decompress(base64.b64decode(data)))
    messages = [e["message"] for e in payload.get("logEvents", [])]
    print("SIM2REAL_MARKER:" + json.dumps({"messages": messages}))
    return {"ok": True}
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


def _wait_for_effect(
    probe, predicate, timeout_s=120.0, interval_s=2.0, description="effect"
):
    """Poll for an async cross-service effect."""
    return _poll_until(
        probe,
        predicate,
        timeout_s=timeout_s,
        interval_s=interval_s,
        description=description,
    )


def _make_zip(code: str) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("lambda_function.py", code)
    return buf.getvalue()


def _create_lambda_role(ctx) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-lgcwlam-role-")
    trust_policy = {
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
        AssumeRolePolicyDocument=json.dumps(trust_policy),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]["Arn"]
    policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)

    def _cleanup():
        iam.detach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
        iam.delete_role(RoleName=role_name)

    ctx.on_cleanup(_cleanup)
    return role_arn


def _create_marker_function(ctx, role_arn: str, code: str, timeout: int = 30) -> str:
    lam = ctx.client("lambda")
    function_name = ctx.unique_name("sim2real-lgcwlam-fn-")
    zip_bytes = _make_zip(code)

    def _try():
        try:
            return lam.create_function(
                FunctionName=function_name,
                Runtime="python3.12",
                Role=role_arn,
                Handler="lambda_function.handler",
                Code={"ZipFile": zip_bytes},
                Timeout=timeout,
                Publish=True,
                Tags={"sim2real": CHECK},
            )
        except lam.exceptions.InvalidParameterValueException as exc:
            if "role" in str(exc).lower():
                return None
            raise

    _poll_until(
        _try,
        lambda r: r is not None,
        timeout_s=60,
        interval_s=3.0,
        description="lambda create (role propagation)",
    )
    ctx.on_cleanup(lambda: lam.delete_function(FunctionName=function_name))
    _poll_until(
        lambda: lam.get_function(FunctionName=function_name)["Configuration"]["State"],
        lambda s: s == "Active",
        timeout_s=60,
        interval_s=3.0,
        description=f"function {function_name} Active",
    )
    return function_name


def _collect_decoded_messages(ctx, function_name: str, since_ms: int) -> list[str]:
    logs = ctx.client("logs")
    log_group = f"/aws/lambda/{function_name}"
    try:
        resp = logs.filter_log_events(logGroupName=log_group, startTime=since_ms)
    except logs.exceptions.ResourceNotFoundException:
        return []
    found: list[str] = []
    for ev in resp.get("events", []):
        msg = ev["message"]
        if "SIM2REAL_MARKER:" not in msg:
            continue
        try:
            payload = json.loads(msg.split("SIM2REAL_MARKER:", 1)[1])
        except (ValueError, IndexError):
            continue
        found.extend(payload.get("messages", []))
    return found


def _wait_for_decoded_messages(
    ctx, function_name: str, since_ms: int, contains: str, timeout_s=120.0, interval_s=5.0
) -> list[str]:
    return _wait_for_effect(
        lambda: _collect_decoded_messages(ctx, function_name, since_ms),
        lambda r: any(contains in m for m in r),
        timeout_s=timeout_s,
        interval_s=interval_s,
        description=f"decoded log message containing {contains!r} delivered to {function_name}",
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
