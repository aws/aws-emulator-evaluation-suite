"""lambda-rds-missing-permission-denied."""
from __future__ import annotations

import io
import json
import time
import zipfile

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "lambda-rds-missing-permission-denied"
GROUP = "permission-boundary"
SERVICES = ["lambda", "rds", "secretsmanager"]

_HANDLER = """
import boto3
import botocore.exceptions

def handler(event, context):
    rds = boto3.client("rds", region_name=event["region"])
    try:
        resp = rds.describe_db_instances(MaxRecords=20)
        return {"ok": True, "count": len(resp["DBInstances"])}
    except botocore.exceptions.ClientError as exc:
        return {"ok": False, "code": exc.response["Error"]["Code"]}
"""


@tags("axis:rejection", "cap:c3", "cap:c7", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """A Lambda role with no rds:DescribeDBInstances permission is denied when calling the RDS
    API, while an otherwise-identical role that grants the permission succeeds."""
    allowed_role_arn, _ = _create_lambda_role(
        ctx,
        statements=[{"Effect": "Allow", "Action": "rds:DescribeDBInstances", "Resource": "*"}],
    )
    denied_role_arn, _ = _create_lambda_role(ctx, statements=[])

    allowed_fn = _create_function(ctx, allowed_role_arn, _zip_bytes(_HANDLER))
    denied_fn = _create_function(ctx, denied_role_arn, _zip_bytes(_HANDLER))

    # positive control: role with the permission succeeds (regardless of how many instances exist)
    ok_result = _invoke(ctx, allowed_fn, {"region": ctx.region})
    assert ok_result["ok"] is True, f"expected the granted role to succeed calling RDS, got {ok_result}"
    assert isinstance(ok_result["count"], int), f"expected an int DBInstances count, got {ok_result!r}"

    # negative: role with zero rds permissions is denied by IAM before RDS even runs the call
    denied_result = _invoke(ctx, denied_fn, {"region": ctx.region})
    assert denied_result["ok"] is False, f"expected the ungranted role to be denied, got {denied_result}"
    assert denied_result["code"] == "AccessDenied", (
        f"expected error code AccessDenied for the ungranted role, got {denied_result['code']!r}"
    )


# ===== helpers =====


def _zip_bytes(handler_code: str) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("index.py", handler_code)
    return buf.getvalue()


def _create_lambda_role(ctx, statements):
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    role_arn = iam.create_role(RoleName=name, AssumeRolePolicyDocument=json.dumps(trust))["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=name))
    managed_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
    iam.attach_role_policy(RoleName=name, PolicyArn=managed_arn)
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=name, PolicyArn=managed_arn))
    if statements:
        iam.put_role_policy(
            RoleName=name,
            PolicyName="inline-perms",
            PolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": statements}),
        )
        ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=name, PolicyName="inline-perms"))
    return role_arn, name


def _create_function(ctx, role_arn, zip_bytes, timeout=30, vpc_config=None, env=None):
    lam = ctx.client("lambda")
    name = ctx.unique_name("sim2real-fn-")
    kwargs = dict(
        FunctionName=name,
        Runtime="python3.12",
        Role=role_arn,
        Handler="index.handler",
        Code={"ZipFile": zip_bytes},
        Timeout=timeout,
        MemorySize=256,
        Publish=True,
    )
    if vpc_config:
        kwargs["VpcConfig"] = vpc_config
    if env:
        kwargs["Environment"] = {"Variables": env}
    ctx.on_cleanup(lambda _n=name: _delete_lambda_log_group(ctx, _n))
    # IAM role propagation: retry the create on its documented error for up to 60 s.
    deadline = time.monotonic() + 60
    left = ctx.time_left()
    if left is not None:
        deadline = min(deadline, time.monotonic() + max(1.0, left - 5.0))
    while True:
        try:
            lam.create_function(**kwargs)
            break
        except lam.exceptions.InvalidParameterValueException:
            if time.monotonic() >= deadline:
                raise
            time.sleep(2)
    ctx.on_cleanup(lambda: lam.delete_function(FunctionName=name))
    lam.get_waiter("function_active_v2").wait(FunctionName=name, WaiterConfig={"Delay": 2, "MaxAttempts": 150})
    return name


def _invoke(ctx, name, payload):
    lam = ctx.client("lambda")
    resp = lam.invoke(FunctionName=name, Payload=json.dumps(payload).encode(), InvocationType="RequestResponse")
    raw = resp["Payload"].read()
    body = json.loads(raw) if raw else None
    if resp.get("FunctionError"):
        raise AssertionError(f"lambda invocation failed ({resp['FunctionError']}): {body}")
    return body


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
