"""logs-subscription-filter-invokes-lambda-positive."""
from __future__ import annotations

import io
import json
import time
import zipfile

from behavioral_harness import tags

CHECK = "logs-subscription-filter-invokes-lambda-positive"
GROUP = "event-propagation"
SERVICES = ["cloudwatch", "lambda", "logs"]


@tags("axis:happy-path", "cap:c2", "cap:c3", "concern:data-plane", "concern:e2e", "concern:eventing", "dp:api", "plane:data")
def run(ctx) -> None:
    """A CloudWatch Logs subscription filter with a Lambda destination invokes the function
    for a log event written to the subscribed log group, and the payload delivered to the
    function decodes (base64+gzip) to the exact original log message."""
    lam = ctx.client("lambda")
    logs = ctx.client("logs")

    role_arn = _create_lambda_role(ctx)
    function_name = _create_marker_function(ctx, role_arn, _LAMBDA_CODE_LOGS)
    function_arn = lam.get_function(FunctionName=function_name)["Configuration"]["FunctionArn"]

    log_group_name = ctx.unique_name("sim2real-lgcwlam-lg-")
    logs.create_log_group(logGroupName=log_group_name, tags=_MANAGED_TAGS)
    ctx.on_cleanup(lambda: logs.delete_log_group(logGroupName=log_group_name))
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

    filter_name = ctx.unique_name("sim2real-subfilter-")
    logs.put_subscription_filter(
        logGroupName=log_group_name,
        filterName=filter_name,
        filterPattern="",
        destinationArn=function_arn,
    )
    ctx.on_cleanup(
        lambda: logs.delete_subscription_filter(logGroupName=log_group_name, filterName=filter_name)
    )

    since_ms = int(time.time() * 1000)
    unique_message = ctx.unique_name("sim2real-log-event-")
    stream_name = ctx.unique_name("sim2real-stream-")
    logs.create_log_stream(logGroupName=log_group_name, logStreamName=stream_name)

    messages = _emit_until_decoded(
        ctx, logs, log_group_name, stream_name, function_name, since_ms, unique_message
    )
    assert any(unique_message in m for m in messages), f"expected {unique_message!r} in {messages!r}"


_MANAGED_TAGS = {"sim2real:managed": "true"}

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
        Tags=[{"Key": k, "Value": v} for k, v in _MANAGED_TAGS.items()],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=policy_arn))
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
                Tags=_MANAGED_TAGS,
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


def _emit_until_decoded(
    ctx,
    logs,
    log_group_name: str,
    stream_name: str,
    function_name: str,
    since_ms: int,
    message: str,
    *,
    attempts: int = 8,
    poll_s: float = 15.0,
) -> list[str]:
    """Write the log line repeatedly until it is decoded from the destination's own logs.

    A freshly created subscription filter can drop the first events it receives before the
    Logs -> Lambda delivery path is live, and CloudWatch Logs does not retry a dropped
    delivery, so re-emitting on a bounded schedule is more reliable than one write plus a
    single long wait.
    """
    found: list[str] = []
    for _ in range(attempts):
        logs.put_log_events(
            logGroupName=log_group_name,
            logStreamName=stream_name,
            logEvents=[{"timestamp": int(time.time() * 1000), "message": message}],
        )
        attempt_end = time.monotonic() + poll_s
        while True:
            found = _collect_decoded_messages(ctx, function_name, since_ms)
            if any(message in m for m in found):
                return found
            if time.monotonic() >= attempt_end:
                break
            time.sleep(5.0)
    raise AssertionError(
        f"subscription filter never delivered a log event containing {message!r} to "
        f"{function_name} after {attempts} attempts; last decoded messages {found!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
