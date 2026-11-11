"""lambda-rds-describedbinstances-positive."""
from __future__ import annotations

import io
import json
import time
import zipfile
from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "lambda-rds-describedbinstances-positive"
GROUP = "sdk-call"
SERVICES = ["lambda", "rds", "secretsmanager"]


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "concern:e2e", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """A Lambda function whose role grants rds:DescribeDBInstances lists real DB metadata."""
    rds = ctx.client("rds")
    db_id = ctx.unique_name("sim2real-rdsdesc-")
    subnet_group = _network_db_subnet_group(ctx, rds)
    rds.create_db_instance(
        DBInstanceIdentifier=db_id,
        Engine="postgres",
        DBInstanceClass="db.t4g.micro",
        MasterUsername="dbadmin",
        ManageMasterUserPassword=True,
        AllocatedStorage=20,
        BackupRetentionPeriod=0,
        PubliclyAccessible=False,
        Tags=[{"Key": "sim2real", "Value": "true"}],
        DBSubnetGroupName=subnet_group,
    )
    ctx.on_cleanup(lambda: _delete_instance(ctx, db_id))
    inst = _wait_db_instance_available(ctx, db_id, timeout_s=1200)
    assert inst["DBInstanceStatus"] == "available", f"expected available, got {inst['DBInstanceStatus']!r}"

    role_arn, role_name = _create_lambda_role(
        ctx,
        [{"Effect": "Allow", "Action": "rds:DescribeDBInstances", "Resource": "*"}],
    )
    fn_name = _create_lambda_function(ctx, role_arn, _CODE_DESCRIBE)

    body = _invoke_lambda(ctx, fn_name, {"db_instance_id": db_id})
    assert body["success"] is True, f"expected a successful describe, got {body}"
    assert "code" not in body, f"expected no error code on success, got {body}"
    data = body["data"]
    assert data["identifier"] == db_id, f"expected identifier {db_id!r}, got {data['identifier']!r}"
    assert data["engine"] == "postgres", f"expected engine 'postgres', got {data['engine']!r}"
    assert data["instance_class"] == "db.t4g.micro", f"expected instance_class 'db.t4g.micro', got {data['instance_class']!r}"
    assert data["status"] == "available", f"expected status 'available', got {data['status']!r}"


_CODE_DESCRIBE = """
import boto3
from botocore.exceptions import ClientError

def handler(event, context):
    client = boto3.client("rds")
    try:
        resp = client.describe_db_instances(DBInstanceIdentifier=event["db_instance_id"])
        inst = resp["DBInstances"][0]
        return {
            "success": True,
            "data": {
                "identifier": inst["DBInstanceIdentifier"],
                "engine": inst["Engine"],
                "instance_class": inst["DBInstanceClass"],
                "status": inst["DBInstanceStatus"],
            },
        }
    except ClientError as exc:
        return {"success": False, "code": exc.response["Error"]["Code"], "data": None}
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


def _wait_db_instance_available(ctx, db_id: str, timeout_s: float = 1200.0) -> dict[str, Any]:
    rds = ctx.client("rds")

    def probe():
        return rds.describe_db_instances(DBInstanceIdentifier=db_id)["DBInstances"][0]

    return _poll_until(probe, lambda i: i["DBInstanceStatus"] == "available", timeout_s=timeout_s, interval_s=20.0)


def _delete_instance(ctx, db_id: str) -> None:
    rds = ctx.client("rds")
    try:
        rds.delete_db_instance(DBInstanceIdentifier=db_id, SkipFinalSnapshot=True)
    except rds.exceptions.DBInstanceNotFoundFault:
        pass


def _lambda_zip_bytes(code: str, filename: str = "index.py") -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr(filename, code)
    return buf.getvalue()


def _create_lambda_role(ctx, statements: list[dict]) -> tuple[str, str]:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-rdsdesc-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    role = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust))
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


def _create_lambda_function(ctx, role_arn: str, code: str, timeout: int = 60) -> str:
    lam = ctx.client("lambda")
    fn_name = ctx.unique_name("sim2real-rdsdesc-fn-")
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


def _invoke_lambda(ctx, fn_name: str, payload: dict) -> dict:
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


def _network_db_subnet_group(ctx, client) -> str:
    """A DB subnet group over the run's shared network, deleted once nothing uses it."""
    name = ctx.unique_name("sim2real-net-dbsg-")
    client.create_db_subnet_group(
        DBSubnetGroupName=name,
        DBSubnetGroupDescription="sim2real shared network",
        SubnetIds=ctx.network().subnet_ids,
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
    )
    ctx.on_cleanup(
        lambda: _delete_when_released(
            lambda: client.delete_db_subnet_group(DBSubnetGroupName=name),
            ("InvalidDBSubnetGroupStateFault", "InvalidDBSubnetGroupState"),
            ("DBSubnetGroupNotFoundFault",),
        )
    )
    return name


def _delete_when_released(delete, busy_codes, gone_codes, timeout_s=1500.0, interval_s=15.0):
    """Delete a subnet group, retrying while a resource that is being deleted still uses it."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            delete()
            return
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code in gone_codes:
                return
            if code not in busy_codes or time.monotonic() >= deadline:
                raise
        time.sleep(interval_s)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
