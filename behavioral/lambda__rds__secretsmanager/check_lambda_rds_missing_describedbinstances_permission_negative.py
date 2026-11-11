"""lambda-rds-missing-describedbinstances-permission-negative."""
from __future__ import annotations

import io
import json
import time
import zipfile
from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "lambda-rds-missing-describedbinstances-permission-negative"
GROUP = "permission-boundary"
SERVICES = ["lambda", "rds", "secretsmanager"]


@tags("axis:rejection", "cap:c3", "cap:c7", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """A Lambda role lacking rds:DescribeDBInstances is denied; granting it unblocks the call."""
    fake_db_id = ctx.unique_name("sim2real-nodescperm-")

    role_arn, role_name = _create_lambda_role(ctx, statements=None)
    fn_name = _create_lambda_function(ctx, role_arn, _CODE_DESCRIBE)

    denied = _invoke_lambda(ctx, fn_name, {"db_instance_id": fake_db_id})
    assert denied["success"] is False, f"expected the call to be denied with no rds permission, got {denied!r}"
    # RDS (Query protocol) returns "AccessDenied"
    assert "AccessDenied" in denied["code"], f"expected AccessDenied error code, got {denied['code']!r}"
    assert denied.get("data") is None, f"expected no metadata leaked while denied, got {denied.get('data')!r}"

    # Positive control: grant the permission and confirm the block was specifically
    # this missing permission -- the call should now reach RDS's resource lookup and
    # fail differently (DBInstanceNotFound, since the id is a placeholder), not AccessDeniedException.
    iam = ctx.client("iam")
    policy_name = f"{role_name}-inline"
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName=policy_name,
        PolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [{"Effect": "Allow", "Action": "rds:DescribeDBInstances", "Resource": "*"}],
            }
        ),
    )
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name))

    final = _poll_until(
        lambda: _invoke_lambda(ctx, fn_name, {"db_instance_id": fake_db_id}),
        lambda body: "AccessDenied" not in (body["code"] or ""),
        timeout_s=90.0,
        interval_s=5.0,
    )
    assert final["success"] is False, f"expected the fake db id to still fail after granting permission, got {final!r}"
    assert final["code"] == "DBInstanceNotFound", (
        f"expected the call to reach RDS's own resource lookup once permission was granted "
        f"(DBInstanceNotFound for a placeholder id), got {final['code']!r}"
    )
    assert final["message"] == f"DBInstance {fake_db_id} not found.", final


_CODE_DESCRIBE = """
import boto3
from botocore.exceptions import ClientError

def handler(event, context):
    client = boto3.client("rds")
    try:
        resp = client.describe_db_instances(DBInstanceIdentifier=event["db_instance_id"])
        inst = resp["DBInstances"][0]
        return {"success": True, "code": None, "data": {"identifier": inst["DBInstanceIdentifier"]}}
    except ClientError as exc:
        err = exc.response["Error"]
        return {"success": False, "code": err["Code"], "message": err.get("Message"), "data": None}
"""


def _poll_until(probe, predicate, timeout_s=60.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last={last}")


def _lambda_zip_bytes(code: str, filename: str = "index.py") -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr(filename, code)
    return buf.getvalue()


def _create_lambda_role(ctx, statements: list[dict] | None) -> tuple[str, str]:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-nodescperm-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": "true"}],
    )
    role_arn = role["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    basic_policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=basic_policy_arn)
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=basic_policy_arn))
    if statements:
        policy_name = f"{role_name}-inline"
        iam.put_role_policy(
            RoleName=role_name,
            PolicyName=policy_name,
            PolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": statements}),
        )
        ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name))
    return role_arn, role_name


def _create_lambda_function(ctx, role_arn: str, code: str, timeout: int = 30) -> str:
    lam = ctx.client("lambda")
    fn_name = ctx.unique_name("sim2real-nodescperm-fn-")
    zip_bytes = _lambda_zip_bytes(code)
    last_err: Exception | None = None
    for _ in range(10):
        try:
            ctx.on_cleanup(lambda _n=fn_name: _delete_lambda_log_group(ctx, _n))
            lam.create_function(
                FunctionName=fn_name,
                Runtime="python3.12",
                Role=role_arn,
                Handler="index.handler",
                Code={"ZipFile": zip_bytes},
                Timeout=timeout,
                Tags={"sim2real": "true"},
            )
            break
        except lam.exceptions.InvalidParameterValueException as exc:
            last_err = exc
            time.sleep(3)
    else:
        raise last_err
    ctx.on_cleanup(lambda: lam.delete_function(FunctionName=fn_name))
    lam.get_waiter("function_active_v2").wait(FunctionName=fn_name, WaiterConfig={"Delay": 2, "MaxAttempts": 150})
    return fn_name


def _invoke_lambda(ctx, fn_name: str, payload: dict) -> dict[str, Any]:
    lam = ctx.client("lambda")
    last_err: Exception | None = None
    deadline = time.monotonic() + 60.0
    while time.monotonic() < deadline:
        try:
            resp = lam.invoke(FunctionName=fn_name, Payload=json.dumps(payload).encode())
            body = json.loads(resp["Payload"].read())
            if resp.get("FunctionError"):
                raise AssertionError(f"lambda invocation errored: {body}")
            return body
        except lam.exceptions.InvalidParameterValueException as exc:
            last_err = exc
            time.sleep(5)
            continue
    raise last_err if last_err else AssertionError("invoke never succeeded")


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
