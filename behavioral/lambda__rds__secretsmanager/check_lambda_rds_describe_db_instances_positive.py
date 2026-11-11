"""lambda-rds-describe-db-instances-positive."""

from __future__ import annotations

import io
import json
import time
import zipfile

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "lambda-rds-describe-db-instances-positive"
GROUP = "sdk-call"
SERVICES = ["lambda", "rds", "secretsmanager"]

_HANDLER = """
import boto3

def handler(event, context):
    rds = boto3.client("rds", region_name=event["region"])
    resp = rds.describe_db_instances(DBInstanceIdentifier=event["db_instance_id"])
    inst = resp["DBInstances"][0]
    return {
        "identifier": inst["DBInstanceIdentifier"],
        "engine": inst["Engine"],
        "status": inst["DBInstanceStatus"],
        "instance_class": inst["DBInstanceClass"],
    }
"""


@tags(
    "axis:happy-path",
    "cap:c3",
    "concern:data-plane",
    "concern:e2e",
    "concern:representation",
    "dp:api",
    "plane:data",
)
def run(ctx) -> None:
    """A Lambda whose role grants rds:DescribeDBInstances lists real DB instance metadata via boto3."""
    rds = ctx.client("rds")
    db_id = ctx.unique_name("sim2real-rds-")
    subnet_group = _network_db_subnet_group(ctx, rds)
    rds.create_db_instance(
        DBInstanceIdentifier=db_id,
        DBInstanceClass="db.t3.micro",
        Engine="mysql",
        MasterUsername="admin",
        MasterUserPassword="TmpPassw0rd!2024",
        AllocatedStorage=20,
        PubliclyAccessible=False,
        BackupRetentionPeriod=0,
        Tags=[{"Key": "sim2real", "Value": "true"}],
        DBSubnetGroupName=subnet_group,
    )
    _register_instance_cleanup(ctx, rds, db_id)

    role_arn, _role_name = _create_lambda_role(
        ctx,
        statements=[
            {"Effect": "Allow", "Action": "rds:DescribeDBInstances", "Resource": "*"},
        ],
    )
    fn_name = _create_function(ctx, role_arn, _zip_bytes(_HANDLER))

    result = _invoke(ctx, fn_name, {"region": ctx.region, "db_instance_id": db_id})
    assert result["identifier"] == db_id, (
        f"expected identifier {db_id!r}, got {result['identifier']!r}"
    )
    assert result["engine"] == "mysql", (
        f"expected engine 'mysql', got {result['engine']!r}"
    )
    assert result["instance_class"] == "db.t3.micro", (
        f"expected instance_class 'db.t3.micro', got {result['instance_class']!r}"
    )
    # the instance was just created, so it is still transitioning through its lifecycle -
    # any valid non-terminal status confirms the Lambda genuinely reached the RDS API
    assert result["status"] in {
        "creating",
        "backing-up",
        "configuring-enhanced-monitoring",
        "available",
        "modifying",
    }, f"unexpected DB instance status observed via Lambda: {result['status']!r}"


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
            {
                "Effect": "Allow",
                "Principal": {"Service": "lambda.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    role_arn = iam.create_role(
        RoleName=name, AssumeRolePolicyDocument=json.dumps(trust)
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=name))
    managed_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
    iam.attach_role_policy(RoleName=name, PolicyArn=managed_arn)
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=name, PolicyArn=managed_arn))
    if statements:
        iam.put_role_policy(
            RoleName=name,
            PolicyName="inline-perms",
            PolicyDocument=json.dumps(
                {"Version": "2012-10-17", "Statement": statements}
            ),
        )
        ctx.on_cleanup(
            lambda: iam.delete_role_policy(RoleName=name, PolicyName="inline-perms")
        )
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
    resp = lam.invoke(
        FunctionName=name,
        Payload=json.dumps(payload).encode(),
        InvocationType="RequestResponse",
    )
    raw = resp["Payload"].read()
    body = json.loads(raw) if raw else None
    if resp.get("FunctionError"):
        raise AssertionError(
            f"lambda invocation failed ({resp['FunctionError']}): {body}"
        )
    return body


def _register_instance_cleanup(ctx, rds, db_id):
    def _cleanup():
        # RDS rejects DeleteDBInstance while a create/modify is still in flight; see
        # https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/USER_CreateDBInstance.html
        deadline = time.monotonic() + 1200
        while time.monotonic() < deadline:
            try:
                inst = rds.describe_db_instances(DBInstanceIdentifier=db_id)[
                    "DBInstances"
                ][0]
            except rds.exceptions.DBInstanceNotFoundFault:
                return
            if inst["DBInstanceStatus"] not in ("creating", "backing-up", "modifying"):
                break
            time.sleep(15)
        try:
            rds.delete_db_instance(
                DBInstanceIdentifier=db_id,
                SkipFinalSnapshot=True,
                DeleteAutomatedBackups=True,
            )
        except rds.exceptions.DBInstanceNotFoundFault:
            pass

    ctx.on_cleanup(_cleanup)


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
