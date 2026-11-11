"""lambda-rds-data-api-execute-statement-positive."""

from __future__ import annotations

import io
import json
import time
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "lambda-rds-data-api-execute-statement-positive"
GROUP = "sdk-call"
SERVICES = ["lambda", "rds", "secretsmanager"]

_HANDLER = """
import boto3
from botocore.exceptions import ClientError

def handler(event, context):
    try:
        return _run(event)
    except ClientError as exc:
        return {"error": {"code": exc.response["Error"]["Code"],
                          "message": exc.response["Error"]["Message"]}}

def _run(event):
    client = boto3.client("rds-data", region_name=event["region"])
    common = dict(
        resourceArn=event["cluster_arn"],
        secretArn=event["secret_arn"],
        database=event["database"],
    )
    client.execute_statement(
        sql="CREATE TABLE IF NOT EXISTS sim2real_probe (id INT PRIMARY KEY, val VARCHAR(64))",
        **common,
    )
    client.execute_statement(
        sql=(
            "INSERT INTO sim2real_probe (id, val) VALUES (1, 'hello-data-api') "
            "ON DUPLICATE KEY UPDATE val = VALUES(val)"
        ),
        **common,
    )
    resp = client.execute_statement(sql="SELECT val FROM sim2real_probe WHERE id = 1", **common)
    return {"records": resp["records"]}
"""


@tags(
    "axis:happy-path",
    "cap:c3",
    "cap:c4",
    "concern:data-plane",
    "concern:e2e",
    "dp:api",
    "plane:data",
)
def run(ctx) -> None:
    """A Lambda granted rds-data:ExecuteStatement and secretsmanager:GetSecretValue queries an
    Aurora Serverless v2 cluster over the RDS Data API with the RDS-managed admin secret and
    gets real result rows."""
    rds = ctx.client("rds")
    cluster_id = ctx.unique_name("sim2real-auroracluster-")
    db_name = "testdb"
    subnet_group = _create_db_subnet_group(ctx)

    create_resp = rds.create_db_cluster(
        DBClusterIdentifier=cluster_id,
        DBSubnetGroupName=subnet_group,
        Engine="aurora-mysql",
        MasterUsername="admin",
        ManageMasterUserPassword=True,
        DatabaseName=db_name,
        EnableHttpEndpoint=True,
        ServerlessV2ScalingConfiguration={"MinCapacity": 0.5, "MaxCapacity": 2.0},
        BackupRetentionPeriod=1,
        Tags=[{"Key": "sim2real", "Value": "true"}],
    )["DBCluster"]
    cluster_arn = create_resp["DBClusterArn"]
    secret_arn = create_resp["MasterUserSecret"]["SecretArn"]
    _register_cluster_cleanup(ctx, rds, cluster_id)

    instance_id = ctx.unique_name("sim2real-aurorainst-")
    rds.create_db_instance(
        DBInstanceIdentifier=instance_id,
        DBInstanceClass="db.serverless",
        Engine="aurora-mysql",
        DBClusterIdentifier=cluster_id,
        Tags=[{"Key": "sim2real", "Value": "true"}],
    )
    _register_instance_cleanup(ctx, rds, instance_id)

    _wait_cluster_available(rds, cluster_id, timeout_s=1500)
    _wait_instance_available(rds, instance_id, timeout_s=900)

    role_arn, _role_name = _create_lambda_role(
        ctx,
        statements=[
            {
                "Effect": "Allow",
                "Action": "rds-data:ExecuteStatement",
                "Resource": cluster_arn,
            },
            {
                "Effect": "Allow",
                "Action": "secretsmanager:GetSecretValue",
                "Resource": secret_arn,
            },
        ],
    )
    fn_name = _create_function(ctx, role_arn, _zip_bytes(_HANDLER), timeout=60)

    payload = {
        "region": ctx.region,
        "cluster_arn": cluster_arn,
        "secret_arn": secret_arn,
        "database": db_name,
    }

    # the HTTP Data API endpoint can take a short while to become fully live after the cluster
    # itself reports "available"; poll the real ExecuteStatement round trip for that window
    deadline = time.monotonic() + 300
    result = _invoke(ctx, fn_name, payload)
    while "error" in result and time.monotonic() < deadline:
        time.sleep(2)
        result = _invoke(ctx, fn_name, payload)
    assert "error" not in result, f"Data API never became usable via Lambda: {result['error']}"

    records = result["records"]
    assert len(records) == 1, (
        f"expected exactly 1 row from the independent SELECT, got {records!r}"
    )
    value = records[0][0].get("stringValue")
    assert value == "hello-data-api", (
        f"expected the value written by the earlier INSERT to read back as 'hello-data-api', got {value!r}"
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


def _wait_cluster_available(rds, cluster_id, timeout_s=1500, interval_s=20):
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        cluster = rds.describe_db_clusters(DBClusterIdentifier=cluster_id)[
            "DBClusters"
        ][0]
        if cluster["Status"] == "available":
            return cluster
        if cluster["Status"] in ("failed",):
            raise AssertionError(f"cluster entered status {cluster['Status']!r}")
        time.sleep(interval_s)
    raise AssertionError(
        f"cluster {cluster_id} did not become available within {timeout_s}s"
    )


def _wait_instance_available(rds, instance_id, timeout_s=900, interval_s=20):
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        inst = rds.describe_db_instances(DBInstanceIdentifier=instance_id)[
            "DBInstances"
        ][0]
        if inst["DBInstanceStatus"] == "available":
            return inst
        if inst["DBInstanceStatus"] in ("failed",):
            raise AssertionError(
                f"instance entered status {inst['DBInstanceStatus']!r}"
            )
        time.sleep(interval_s)
    raise AssertionError(
        f"instance {instance_id} did not become available within {timeout_s}s"
    )


def _register_instance_cleanup(ctx, rds, instance_id):
    def _cleanup():
        deadline = time.monotonic() + 1200
        while time.monotonic() < deadline:
            try:
                inst = rds.describe_db_instances(DBInstanceIdentifier=instance_id)[
                    "DBInstances"
                ][0]
            except rds.exceptions.DBInstanceNotFoundFault:
                return
            if inst["DBInstanceStatus"] not in ("creating", "backing-up", "modifying"):
                break
            time.sleep(15)
        try:
            rds.delete_db_instance(
                DBInstanceIdentifier=instance_id, SkipFinalSnapshot=True
            )
        except rds.exceptions.DBInstanceNotFoundFault:
            pass

    ctx.on_cleanup(_cleanup)


def _register_cluster_cleanup(ctx, rds, cluster_id):
    def _cleanup():
        # the cluster can only be deleted once it has no remaining member instances and is not
        # mid-transition; the instance cleanup above is registered after this one and therefore
        # (LIFO) runs first, removing the sole member instance before we get here
        deadline = time.monotonic() + 1200
        while time.monotonic() < deadline:
            try:
                cluster = rds.describe_db_clusters(DBClusterIdentifier=cluster_id)[
                    "DBClusters"
                ][0]
            except rds.exceptions.DBClusterNotFoundFault:
                return
            if cluster["Status"] not in (
                "creating",
                "backing-up",
                "modifying",
                "deleting",
            ):
                break
            time.sleep(15)
        try:
            rds.delete_db_cluster(
                DBClusterIdentifier=cluster_id, SkipFinalSnapshot=True
            )
        except rds.exceptions.DBClusterNotFoundFault:
            return
        # The subnet group teardown that follows needs the cluster gone, not just deleting.
        deadline = time.monotonic() + 1200
        while time.monotonic() < deadline:
            try:
                rds.describe_db_clusters(DBClusterIdentifier=cluster_id)
            except rds.exceptions.DBClusterNotFoundFault:
                return
            time.sleep(20)
        raise AssertionError(f"cluster {cluster_id} was not deleted within 1200s")

    ctx.on_cleanup(_cleanup)


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
