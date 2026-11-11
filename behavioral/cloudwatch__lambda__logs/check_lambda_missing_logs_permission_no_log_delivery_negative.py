"""lambda-missing-logs-permission-no-log-delivery-negative."""
from __future__ import annotations

import io
import json
import time
import zipfile

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "lambda-missing-logs-permission-no-log-delivery-negative"
GROUP = "permission-boundary"
SERVICES = ["cloudwatch", "lambda", "logs"]

_CODE_SIMPLE = """
def lambda_handler(event, context):
    return {"ok": True}
"""


@tags("axis:negative-delivery", "cap:c3", "concern:data-plane", "concern:e2e", "dp:api", "plane:data")
def run(ctx) -> None:
    """Execution role lacking logs:CreateLogStream/PutLogEvents => invocation succeeds but no logs land."""
    # --- broken: role has ONLY the lambda trust policy, no logs permissions at all ---
    bad_role_arn = _create_role(ctx, managed_policy_arns=[])
    bad_fn_name, _ = _create_function(ctx, bad_role_arn, _make_zip(_CODE_SIMPLE))
    bad_log_group = f"/aws/lambda/{bad_fn_name}"
    ctx.on_cleanup(lambda: _delete_log_group_quiet(ctx, bad_log_group))

    lam = ctx.client("lambda")
    resp = lam.invoke(FunctionName=bad_fn_name, InvocationType="RequestResponse")
    # the invocation itself is NOT blocked by the missing logs permission
    assert resp["StatusCode"] == 200, f"expected StatusCode 200 for invoke, got {resp['StatusCode']}"
    assert "FunctionError" not in resp, f"expected no FunctionError, got {resp.get('FunctionError')!r}"

    # generous bounded poll: the log group must never appear because the role can't create it
    log_group = _wait_log_group(ctx, bad_log_group, timeout_s=45)
    assert log_group is None, f"log group unexpectedly appeared despite missing logs permission: {log_group}"

    # --- positive control in the SAME file: identical setup but with logs permission granted ---
    good_role_arn = _create_role(ctx, managed_policy_arns=[
        "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
    ])
    good_fn_name, _ = _create_function(ctx, good_role_arn, _make_zip(_CODE_SIMPLE))
    good_log_group = f"/aws/lambda/{good_fn_name}"
    ctx.on_cleanup(lambda: _delete_log_group_quiet(ctx, good_log_group))

    resp2 = lam.invoke(FunctionName=good_fn_name, InvocationType="RequestResponse")
    assert resp2["StatusCode"] == 200, f"expected StatusCode 200 for positive-control invoke, got {resp2['StatusCode']}"
    good_group = _wait_log_group(ctx, good_log_group, timeout_s=90)
    assert good_group is not None, "positive control never got its log group created"


def _iam_trust_policy() -> str:
    return json.dumps({
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"Service": "lambda.amazonaws.com"},
            "Action": "sts:AssumeRole",
        }],
    })


def _create_role(ctx, managed_policy_arns=(), inline_policies=None) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-behav-role-")
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=_iam_trust_policy(),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    role_arn = role["Role"]["Arn"]
    for arn in managed_policy_arns:
        iam.attach_role_policy(RoleName=role_name, PolicyArn=arn)
    if inline_policies:
        for pname, pdoc in inline_policies.items():
            iam.put_role_policy(RoleName=role_name, PolicyName=pname, PolicyDocument=json.dumps(pdoc))

    def _cleanup():
        for arn in managed_policy_arns:
            try:
                iam.detach_role_policy(RoleName=role_name, PolicyArn=arn)
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "NoSuchEntity":
                    raise
        if inline_policies:
            for pname in inline_policies:
                try:
                    iam.delete_role_policy(RoleName=role_name, PolicyName=pname)
                except ClientError as exc:
                    if exc.response["Error"]["Code"] != "NoSuchEntity":
                        raise
        try:
            iam.delete_role(RoleName=role_name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise

    ctx.on_cleanup(_cleanup)
    return role_arn


def _make_zip(code: str, filename: str = "lambda_function.py") -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr(filename, code)
    return buf.getvalue()


def _create_function(ctx, role_arn, zip_bytes, handler="lambda_function.lambda_handler", env=None, timeout=30):
    lam = ctx.client("lambda")
    fn_name = ctx.unique_name("sim2real-behav-fn-")
    kwargs = dict(
        FunctionName=fn_name,
        Runtime="python3.12",
        Role=role_arn,
        Handler=handler,
        Code={"ZipFile": zip_bytes},
        Timeout=timeout,
        Publish=True,
        Tags={"sim2real": CHECK},
    )
    if env:
        kwargs["Environment"] = {"Variables": env}
    deadline = time.monotonic() + 90
    last_exc = None
    resp = None
    while time.monotonic() < deadline:
        try:
            resp = lam.create_function(**kwargs)
            break
        except lam.exceptions.InvalidParameterValueException as exc:
            last_exc = exc
            time.sleep(3)
    if resp is None:
        raise AssertionError(f"create_function never succeeded (role propagation?): {last_exc}")
    ctx.on_cleanup(lambda: lam.delete_function(FunctionName=fn_name))
    _wait_function_active(ctx, fn_name)
    return fn_name, resp["FunctionArn"]


def _wait_function_active(ctx, fn_name, timeout_s=90):
    lam = ctx.client("lambda")
    deadline = time.monotonic() + timeout_s
    state = None
    while time.monotonic() < deadline:
        state = lam.get_function(FunctionName=fn_name)["Configuration"]["State"]
        if state == "Active":
            return
        time.sleep(2)
    raise AssertionError(f"function never became Active (last state={state})")


def _wait_log_group(ctx, log_group_name, timeout_s=90):
    logs = ctx.client("logs")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        resp = logs.describe_log_groups(logGroupNamePrefix=log_group_name)
        for lg in resp.get("logGroups", []):
            if lg["logGroupName"] == log_group_name:
                return lg
        time.sleep(3)
    return None


def _delete_log_group_quiet(ctx, log_group_name):
    logs = ctx.client("logs")
    try:
        logs.delete_log_group(logGroupName=log_group_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
