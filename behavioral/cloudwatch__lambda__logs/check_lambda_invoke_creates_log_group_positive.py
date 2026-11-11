"""lambda-invoke-creates-log-group-positive."""
from __future__ import annotations

import io
import json
import time
import zipfile

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "lambda-invoke-creates-log-group-positive"
GROUP = "log-delivery"
SERVICES = ["cloudwatch", "lambda", "logs"]

_CODE_SIMPLE = """
def lambda_handler(event, context):
    return {"ok": True}
"""


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "concern:e2e", "dp:api", "plane:data")
def run(ctx) -> None:
    """Invoking a Lambda function creates its /aws/lambda/<name> log group."""
    role_arn = _create_role(ctx, managed_policy_arns=[
        "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
    ])
    fn_name, _ = _create_function(ctx, role_arn, _make_zip(_CODE_SIMPLE))
    log_group_name = f"/aws/lambda/{fn_name}"
    ctx.on_cleanup(lambda: _delete_log_group_quiet(ctx, log_group_name))

    lam = ctx.client("lambda")
    resp = lam.invoke(FunctionName=fn_name, InvocationType="RequestResponse")
    assert resp["StatusCode"] == 200, f"expected invoke StatusCode 200, got {resp['StatusCode']}"

    log_group = _wait_log_group(ctx, log_group_name, timeout_s=90)
    assert log_group is not None, f"log group {log_group_name} never appeared"
    assert log_group["logGroupName"] == log_group_name, (
        f"expected log group name {log_group_name}, got {log_group['logGroupName']}"
    )

    logs = ctx.client("logs")
    logs.delete_log_group(logGroupName=log_group_name)
    still_there = [
        lg for lg in logs.describe_log_groups(logGroupNamePrefix=log_group_name).get("logGroups", [])
        if lg["logGroupName"] == log_group_name
    ]
    assert still_there == [], (
        f"expected {log_group_name} to be gone after DeleteLogGroup, still found {still_there}"
    )


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
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
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
        Tags={"sim2real:managed": "true"},
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
        time.sleep(2)
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
