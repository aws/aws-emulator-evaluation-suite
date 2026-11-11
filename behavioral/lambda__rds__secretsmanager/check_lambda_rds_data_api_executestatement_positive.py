"""lambda-rds-data-api-executestatement-positive."""

from __future__ import annotations

import io
import json
import time
import zipfile
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "lambda-rds-data-api-executestatement-positive"
GROUP = "sdk-call"
SERVICES = ["lambda", "rds", "secretsmanager"]


@tags(
    "axis:happy-path",
    "cap:c2",
    "cap:c3",
    "cap:c4",
    "concern:data-plane",
    "concern:e2e",
    "dp:api",
    "plane:data",
)
def run(ctx) -> None:
    """A Lambda function with rds-data:ExecuteStatement drives real SQL against Aurora via the Data API."""
    cluster = _create_data_api_cluster(ctx)

    role_arn, _role_name = _create_lambda_role(
        ctx,
        [
            {
                "Effect": "Allow",
                "Action": [
                    "rds-data:ExecuteStatement",
                    "rds-data:BatchExecuteStatement",
                ],
                "Resource": cluster["cluster_arn"],
            },
            {
                "Effect": "Allow",
                "Action": "secretsmanager:GetSecretValue",
                "Resource": cluster["secret_arn"],
            },
        ],
    )
    fn_name = _create_lambda_function(ctx, role_arn, _CODE_EXEC, timeout=90)

    body = _poll_until(
        lambda: _invoke_lambda(
            ctx,
            fn_name,
            {
                "resource_arn": cluster["cluster_arn"],
                "secret_arn": cluster["secret_arn"],
                "database": cluster["database"],
            },
        ),
        lambda b: b["success"] is True,
        timeout_s=180.0,
        interval_s=10.0,
    )
    assert body["success"] is True, body
    assert body["value"] == "hello-data-api", (
        f"expected 'hello-data-api', Data API SELECT returned {body['value']!r}"
    )


_CODE_EXEC = """
import boto3
from botocore.exceptions import ClientError

def handler(event, context):
    client = boto3.client("rds-data")
    resource_arn = event["resource_arn"]
    secret_arn = event["secret_arn"]
    database = event["database"]
    try:
        client.execute_statement(
            resourceArn=resource_arn, secretArn=secret_arn, database=database,
            sql="CREATE TABLE IF NOT EXISTS sim2real_probe (id int primary key, val text)",
        )
        client.execute_statement(
            resourceArn=resource_arn, secretArn=secret_arn, database=database,
            sql=(
                "INSERT INTO sim2real_probe (id, val) VALUES (1, 'hello-data-api') "
                "ON CONFLICT (id) DO UPDATE SET val = EXCLUDED.val"
            ),
        )
        resp = client.execute_statement(
            resourceArn=resource_arn, secretArn=secret_arn, database=database,
            sql="SELECT val FROM sim2real_probe WHERE id = 1",
        )
        value = resp["records"][0][0]["stringValue"]
        return {"success": True, "value": value, "code": None}
    except ClientError as exc:
        return {"success": False, "value": None, "code": exc.response["Error"]["Code"]}
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


def _create_data_api_cluster(ctx) -> dict[str, str]:
    rds = ctx.client("rds")
    secretsmanager = ctx.client("secretsmanager")
    cluster_id = ctx.unique_name("sim2real-execcl-")
    instance_id = ctx.unique_name("sim2real-execix-")
    subnet_group = _create_db_subnet_group(ctx)

    resp = rds.create_db_cluster(
        DBClusterIdentifier=cluster_id,
        DBSubnetGroupName=subnet_group,
        Engine="aurora-postgresql",
        MasterUsername="dbadmin",
        ManageMasterUserPassword=True,
        EnableHttpEndpoint=True,
        ServerlessV2ScalingConfiguration={"MinCapacity": 0.5, "MaxCapacity": 2.0},
        BackupRetentionPeriod=1,
        StorageEncrypted=True,
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )
    cluster_arn = resp["DBCluster"]["DBClusterArn"]
    ctx.on_cleanup(lambda: _delete_cluster(ctx, cluster_id))

    rds.create_db_instance(
        DBInstanceIdentifier=instance_id,
        DBClusterIdentifier=cluster_id,
        Engine="aurora-postgresql",
        DBInstanceClass="db.serverless",
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: _delete_instance(ctx, instance_id))

    _wait_db_instance_available(ctx, instance_id, timeout_s=1200)
    described = rds.describe_db_clusters(DBClusterIdentifier=cluster_id)["DBClusters"][
        0
    ]
    secret_arn = described["MasterUserSecret"]["SecretArn"]

    _poll_until(
        lambda: secretsmanager.describe_secret(SecretId=secret_arn),
        lambda d: d.get("ARN") is not None,
        timeout_s=60.0,
        interval_s=5.0,
    )
    return {
        "cluster_id": cluster_id,
        "cluster_arn": cluster_arn,
        "secret_arn": secret_arn,
        "database": "postgres",
    }


def _create_db_subnet_group(ctx) -> str:
    """Create a VPC with two subnets in two AZs and a DB subnet group over them.

    Teardown runs after the cluster teardown (LIFO), retrying while Aurora still holds ENIs.
    """
    ec2 = ctx.client("ec2")
    rds = ctx.client("rds")
    tags = [{"Key": "sim2real", "Value": "true"}]
    vpc_id = ec2.create_vpc(
        CidrBlock="10.80.0.0/16",
        TagSpecifications=[{"ResourceType": "vpc", "Tags": tags}],
    )["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: _retry_dependency(lambda: ec2.delete_vpc(VpcId=vpc_id)))
    zones = sorted(
        z["ZoneName"]
        for z in ec2.describe_availability_zones(
            Filters=[
                {"Name": "state", "Values": ["available"]},
                {"Name": "zone-type", "Values": ["availability-zone"]},
            ]
        )["AvailabilityZones"]
    )[:2]
    subnet_ids = []
    for i, zone in enumerate(zones):
        subnet_id = ec2.create_subnet(
            VpcId=vpc_id,
            CidrBlock=f"10.80.{i}.0/24",
            AvailabilityZone=zone,
            TagSpecifications=[{"ResourceType": "subnet", "Tags": tags}],
        )["Subnet"]["SubnetId"]
        ctx.on_cleanup(
            lambda sid=subnet_id: _retry_dependency(lambda: ec2.delete_subnet(SubnetId=sid))
        )
        subnet_ids.append(subnet_id)
    name = ctx.unique_name("sim2real-subnetgrp-")
    rds.create_db_subnet_group(
        DBSubnetGroupName=name,
        DBSubnetGroupDescription="sim2real behavioral check",
        SubnetIds=subnet_ids,
        Tags=tags,
    )
    ctx.on_cleanup(
        lambda: _retry_dependency(lambda: rds.delete_db_subnet_group(DBSubnetGroupName=name))
    )
    return name


def _retry_dependency(fn, timeout_s: float = 600.0, interval_s: float = 15.0) -> None:
    """Run a network teardown call, retrying while a just-deleted database still holds it."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            fn()
            return
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code.endswith("NotFound") or code.endswith("NotFoundFault"):
                return
            if code not in ("DependencyViolation", "InvalidDBSubnetGroupStateFault"):
                raise
            if time.monotonic() >= deadline:
                raise
        time.sleep(interval_s)


def _wait_db_instance_available(
    ctx, instance_id: str, timeout_s: float = 1200.0
) -> dict[str, Any]:
    rds = ctx.client("rds")

    def probe():
        return rds.describe_db_instances(DBInstanceIdentifier=instance_id)[
            "DBInstances"
        ][0]

    return _poll_until(
        probe,
        lambda i: i["DBInstanceStatus"] == "available",
        timeout_s=timeout_s,
        interval_s=20.0,
    )


def _delete_instance(ctx, instance_id: str) -> None:
    rds = ctx.client("rds")
    try:
        rds.delete_db_instance(DBInstanceIdentifier=instance_id, SkipFinalSnapshot=True)
    except rds.exceptions.DBInstanceNotFoundFault:
        return
    # Best-effort wait: the cluster teardown retries on its own while the instance is still going.
    deadline = time.monotonic() + 300.0
    while time.monotonic() < deadline:
        if _instance_status(ctx, instance_id) is None:
            return
        time.sleep(15.0)


def _instance_status(ctx, instance_id: str) -> str | None:
    rds = ctx.client("rds")
    try:
        return rds.describe_db_instances(DBInstanceIdentifier=instance_id)[
            "DBInstances"
        ][0]["DBInstanceStatus"]
    except rds.exceptions.DBInstanceNotFoundFault:
        return None


def _delete_cluster(ctx, cluster_id: str) -> None:
    rds = ctx.client("rds")
    deadline = time.monotonic() + 300.0
    while time.monotonic() < deadline:
        try:
            rds.delete_db_cluster(
                DBClusterIdentifier=cluster_id, SkipFinalSnapshot=True
            )
            return
        except rds.exceptions.InvalidDBClusterStateFault:
            time.sleep(15.0)
        except rds.exceptions.DBClusterNotFoundFault:
            return


def _lambda_zip_bytes(code: str, filename: str = "index.py") -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr(filename, code)
    return buf.getvalue()


def _create_lambda_role(ctx, statements: list[dict]) -> tuple[str, str]:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-execapi-role-")
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
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )
    role_arn = role["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    basic_policy_arn = (
        "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
    )
    iam.attach_role_policy(RoleName=role_name, PolicyArn=basic_policy_arn)
    ctx.on_cleanup(
        lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=basic_policy_arn)
    )
    if statements:
        policy_name = f"{role_name}-inline"
        iam.put_role_policy(
            RoleName=role_name,
            PolicyName=policy_name,
            PolicyDocument=json.dumps(
                {"Version": "2012-10-17", "Statement": statements}
            ),
        )
        ctx.on_cleanup(
            lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name)
        )
    return role_arn, role_name


def _create_lambda_function(ctx, role_arn: str, code: str, timeout: int = 60) -> str:
    lam = ctx.client("lambda")
    fn_name = ctx.unique_name("sim2real-execapi-fn-")
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
                Tags={"sim2real-check": CHECK},
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
            resp = lam.invoke(
                FunctionName=fn_name, Payload=json.dumps(payload).encode()
            )
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
