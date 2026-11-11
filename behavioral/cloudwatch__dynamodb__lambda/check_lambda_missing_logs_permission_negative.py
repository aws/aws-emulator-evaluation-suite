"""lambda-missing-logs-permission-negative."""
from __future__ import annotations

import io
import json
import time
import zipfile
from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "lambda-missing-logs-permission-negative"
GROUP = "permission-boundary"
SERVICES = ["cloudwatch", "dynamodb", "lambda"]

_HANDLER_SRC = '''
import os

def handler(event, context):
    print(f"MARKER::{os.environ['MARKER']}")
    return {"ok": True}
'''


@tags("axis:negative-delivery", "cap:c2", "cap:c3", "concern:data-plane", "concern:e2e", "concern:metrics", "dp:api", "plane:data")
def run(ctx) -> None:
    """A Lambda execution role without logs:CreateLogStream/PutLogEvents lets the invocation itself
    succeed (the function code still runs) but no log events are ever delivered to CloudWatch Logs;
    the same handler code with a role that has logging permission (in-file control) does get delivered.
    """
    marker_neg = ctx.unique_name("marker-neg-")
    marker_pos = ctx.unique_name("marker-pos-")

    # Negative: trust policy only, zero attached/inline policies -> no logs:* permission at all.
    neg_role = _create_lambda_role(ctx)
    neg_fn = _create_function(ctx, neg_role, _HANDLER_SRC, env={"MARKER": marker_neg})

    # Positive control: same handler code, role has the standard logging managed policy.
    pos_role = _create_lambda_role(
        ctx, policy_arns=["arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"]
    )
    pos_fn = _create_function(ctx, pos_role, _HANDLER_SRC, env={"MARKER": marker_pos})

    lam = ctx.client("lambda")

    neg_resp = lam.invoke(FunctionName=neg_fn, Payload=b"{}")
    assert neg_resp.get("FunctionError") is None, "invocation itself must succeed despite missing logs permission"
    neg_payload = json.loads(neg_resp["Payload"].read())
    assert neg_payload == {"ok": True}, f"expected {{'ok': True}} from the negative function, got {neg_payload!r}"

    pos_resp = lam.invoke(FunctionName=pos_fn, Payload=b"{}")
    assert pos_resp.get("FunctionError") is None, (
        f"positive control invocation must succeed, got FunctionError={pos_resp.get('FunctionError')!r}"
    )
    pos_payload = json.loads(pos_resp["Payload"].read())
    assert pos_payload == {"ok": True}, f"expected {{'ok': True}} from the positive control, got {pos_payload!r}"

    logs = ctx.client("logs")

    def probe_pos():
        try:
            return logs.filter_log_events(
                logGroupName=f"/aws/lambda/{pos_fn}", filterPattern=f'"{marker_pos}"'
            )["events"]
        except logs.exceptions.ResourceNotFoundException:
            return []

    pos_events = _poll_until(
        probe_pos,
        lambda evs: len(evs) > 0,
        timeout_s=90.0,
        interval_s=5.0,
        label="positive control: logs should be delivered when the role has logging permission",
    )

    # Negative: poll for the same bounded window used successfully by the positive control above;
    # a role lacking logs permission never gets a log group/stream created, so this stays empty.
    # raise_on_timeout=False is intentional here: running out this window
    # with the predicate never true is the expected, passing outcome for a correctly-enforcing
    # target, so the helper must return the empty last-observed value rather than raise.
    def probe_neg():
        try:
            return logs.filter_log_events(
                logGroupName=f"/aws/lambda/{neg_fn}", filterPattern=f'"{marker_neg}"'
            )["events"]
        except logs.exceptions.ResourceNotFoundException:
            return []

    neg_events = _poll_until(
        probe_neg, lambda evs: len(evs) > 0, timeout_s=90.0, interval_s=5.0, raise_on_timeout=False
    )
    assert neg_events == [], f"expected no log events without logs permission, found {neg_events}"


def _poll_until(probe, predicate, timeout_s=60.0, interval_s=3.0, label="condition", raise_on_timeout=True):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    if raise_on_timeout:
        raise AssertionError(f"{label}: not met within {timeout_s}s; last observed {last!r}")
    return last


def _zip_bytes(filename: str, source: str) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr(filename, source)
    return buf.getvalue()


def _create_lambda_role(ctx, policy_arns=None, inline_policies=None) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-cwlam-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    role_arn = role["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    for arn in policy_arns or []:
        iam.attach_role_policy(RoleName=role_name, PolicyArn=arn)
        ctx.on_cleanup(lambda a=arn: iam.detach_role_policy(RoleName=role_name, PolicyArn=a))
    for i, doc in enumerate(inline_policies or []):
        pname = f"inline-{i}"
        iam.put_role_policy(RoleName=role_name, PolicyName=pname, PolicyDocument=json.dumps(doc))
        ctx.on_cleanup(lambda p=pname: iam.delete_role_policy(RoleName=role_name, PolicyName=p))
    return role_arn


def _create_function(
    ctx,
    role_arn: str,
    code_source: str,
    handler: str = "lambda_function.handler",
    timeout: int = 30,
    memory: int = 128,
    env: dict[str, str] | None = None,
    reserved_concurrency: int | None = None,
) -> str:
    lam = ctx.client("lambda")
    name = ctx.unique_name("sim2real-cwlam-fn-")
    code_bytes = _zip_bytes("lambda_function.py", code_source)
    kwargs: dict[str, Any] = dict(
        FunctionName=name,
        Runtime="python3.12",
        Role=role_arn,
        Handler=handler,
        Code={"ZipFile": code_bytes},
        Timeout=timeout,
        MemorySize=memory,
        Publish=True,
        Tags={"sim2real": CHECK},
    )
    if env:
        kwargs["Environment"] = {"Variables": env}
    deadline = time.monotonic() + 60.0
    last_err = None
    while time.monotonic() < deadline:
        try:
            ctx.on_cleanup(lambda _n=name: _delete_lambda_log_group(ctx, _n))
            lam.create_function(**kwargs)
            break
        except lam.exceptions.InvalidParameterValueException as err:
            last_err = err
            time.sleep(3.0)
    else:
        raise last_err
    ctx.on_cleanup(lambda: lam.delete_function(FunctionName=name))
    lam.get_waiter("function_active_v2").wait(FunctionName=name, WaiterConfig={"Delay": 2, "MaxAttempts": 150})
    if reserved_concurrency is not None:
        lam.put_function_concurrency(FunctionName=name, ReservedConcurrentExecutions=reserved_concurrency)
    return name


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
