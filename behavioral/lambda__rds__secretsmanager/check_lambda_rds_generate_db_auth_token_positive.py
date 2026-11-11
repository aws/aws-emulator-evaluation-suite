"""lambda-rds-generate-db-auth-token-positive."""
from __future__ import annotations

import io
import json
import os
import time
import zipfile

from behavioral_harness import tags
import secrets

CHECK = "lambda-rds-generate-db-auth-token-positive"
GROUP = "sdk-call"
SERVICES = ["lambda", "rds", "secretsmanager"]

_HANDLER = """
import boto3
import ssl as ssl_lib
import pymysql

def handler(event, context):
    action = event["action"]
    host = event["host"]
    port = int(event["port"])
    if action == "setup":
        conn = pymysql.connect(host=host, port=port, user="admin", password=event["admin_password"],
                                connect_timeout=15)
        try:
            with conn.cursor() as cur:
                cur.execute("CREATE USER IF NOT EXISTS 'iamuser'@'%%' IDENTIFIED WITH AWSAuthenticationPlugin AS 'RDS'")
                cur.execute("GRANT SELECT ON *.* TO 'iamuser'@'%%'")
            conn.commit()
        finally:
            conn.close()
        return {"ok": True}

    if action == "connect":
        client = boto3.client("rds", region_name=event["region"])
        token = client.generate_db_auth_token(DBHostname=host, Port=port, DBUsername="iamuser")
        ctx = ssl_lib.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl_lib.CERT_NONE
        conn = pymysql.connect(
            host=host, port=port, user="iamuser", password=token,
            ssl={"context": ctx}, connect_timeout=15,
            auth_plugin_map={"mysql_clear_password": None},
        )
        try:
            with conn.cursor() as cur:
                cur.execute("SELECT 1")
                row = cur.fetchone()
                cur.execute("SELECT CURRENT_USER()")
                whoami = cur.fetchone()[0]
            return {"ok": True, "value": row[0], "current_user": whoami}
        finally:
            conn.close()

    raise ValueError(f"unknown action {action!r}")
"""


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "concern:e2e", "dp:api", "dp:native", "plane:data")
def run(ctx) -> None:
    """A Lambda function, running inside the DB's VPC, generates an RDS IAM auth token via boto3
    and uses it as the MySQL password to authenticate a real connection and run SELECT 1 - the
    full native protocol round trip, driven entirely by the Lambda execution role's identity."""
    import pymysql  # noqa: F401  (vendored into the Lambda deployment package)

    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]
    ec2 = ctx.client("ec2")
    _vpc_id, subnet_ids, sg_id = _default_vpc_subnets(ctx, ec2)

    rds = ctx.client("rds")
    subnet_group = _create_subnet_group(ctx, rds, subnet_ids)
    db_id = ctx.unique_name("sim2real-rds-iam-")
    admin_password = "Aa1!" + secrets.token_urlsafe(18)
    rds.create_db_instance(
        DBInstanceIdentifier=db_id,
        DBInstanceClass="db.t3.micro",
        Engine="mysql",
        MasterUsername="admin",
        MasterUserPassword=admin_password,
        AllocatedStorage=20,
        VpcSecurityGroupIds=[sg_id],
        DBSubnetGroupName=subnet_group,
        PubliclyAccessible=False,
        EnableIAMDatabaseAuthentication=True,
        BackupRetentionPeriod=0,
        Tags=[{"Key": "sim2real", "Value": "true"}],
    )
    _register_instance_cleanup(ctx, rds, db_id)
    inst = _wait_instance_available(rds, db_id)
    host = inst["Endpoint"]["Address"]
    port = inst["Endpoint"]["Port"]
    dbi_resource_id = inst["DbiResourceId"]

    connect_arn = f"arn:aws:rds-db:{ctx.region}:{account_id}:dbuser:{dbi_resource_id}/iamuser"
    role_arn, _role_name = _create_lambda_role(
        ctx,
        statements=[{"Effect": "Allow", "Action": "rds-db:connect", "Resource": connect_arn}],
        vpc=True,
    )
    zip_bytes = _build_lambda_zip(_HANDLER)
    fn_name = _create_function(
        ctx,
        role_arn,
        zip_bytes,
        timeout=30,
        vpc_config={"SubnetIds": subnet_ids, "SecurityGroupIds": [sg_id]},
    )

    setup = _invoke(ctx, fn_name, {"action": "setup", "host": host, "port": port, "admin_password": admin_password})
    assert setup["ok"] is True, f"lambda 'setup' action did not report ok=True: {setup!r}"

    result = _invoke(ctx, fn_name, {"action": "connect", "host": host, "port": port, "region": ctx.region})
    assert result["ok"] is True, f"lambda 'connect' action did not report ok=True: {result!r}"
    assert result["value"] == 1, f"SELECT 1 over the IAM-token MySQL session returned {result.get('value')!r}, expected 1"
    assert result["current_user"].split("@")[0] == "iamuser", (
        f"the IAM-token session authenticated as the wrong MySQL user: expected 'iamuser', got "
        f"{result.get('current_user')!r}"
    )


# ===== helpers =====


def _build_lambda_zip(handler_code: str) -> bytes:
    import pymysql

    root = os.path.dirname(pymysql.__file__)
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("index.py", handler_code)
        for dirpath, _dirnames, filenames in os.walk(root):
            for fname in filenames:
                if not fname.endswith(".py"):
                    continue
                full = os.path.join(dirpath, fname)
                rel = "pymysql/" + os.path.relpath(full, root).replace(os.sep, "/")
                zf.write(full, rel)
    return buf.getvalue()


def _default_vpc_subnets(ctx, ec2):
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if not vpcs:

        raise AssertionError("no shared network VPC is available in this account/region to place the RDS instance and Lambda")
    vpc_id = vpcs[0]["VpcId"]
    subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}])["Subnets"]
    if len(subnets) < 2:

        raise AssertionError("shared network has fewer than 2 subnets; cannot form a DB subnet group")
    sg = ec2.describe_security_groups(
        Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "group-name", "Values": ["default"]}]
    )["SecurityGroups"][0]["GroupId"]
    return vpc_id, [s["SubnetId"] for s in subnets[:3]], sg


def _create_subnet_group(ctx, rds, subnet_ids):
    name = ctx.unique_name("sim2real-subnetgrp-")
    rds.create_db_subnet_group(
        DBSubnetGroupName=name, DBSubnetGroupDescription="sim2real behavioral check", SubnetIds=subnet_ids
    )
    ctx.on_cleanup(lambda: _retry_while_held(lambda: rds.delete_db_subnet_group(DBSubnetGroupName=name), "InvalidDBSubnetGroupStateFault", timeout_s=1200.0))
    return name


def _create_lambda_role(ctx, statements, vpc=False):
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
    managed = ["arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"]
    if vpc:
        managed.append("arn:aws:iam::aws:policy/service-role/AWSLambdaVPCAccessExecutionRole")
    for arn in managed:
        iam.attach_role_policy(RoleName=name, PolicyArn=arn)
        ctx.on_cleanup(lambda arn=arn: iam.detach_role_policy(RoleName=name, PolicyArn=arn))
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


def _invoke(ctx, name, payload, timeout_s=600):
    lam = ctx.client("lambda")
    deadline = time.monotonic() + timeout_s
    last_body = None
    while time.monotonic() < deadline:
        resp = lam.invoke(FunctionName=name, Payload=json.dumps(payload).encode(), InvocationType="RequestResponse")
        raw = resp["Payload"].read()
        body = json.loads(raw) if raw else None
        if not resp.get("FunctionError"):
            return body
        last_body = body
        # first VPC-attached invocation can be slow while the ENI attaches; retry a couple times
        time.sleep(2)
    raise AssertionError(f"lambda invocation kept failing: {last_body}")


def _wait_instance_available(rds, db_id, timeout_s=1200, interval_s=15):
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        inst = rds.describe_db_instances(DBInstanceIdentifier=db_id)["DBInstances"][0]
        if inst["DBInstanceStatus"] == "available":
            return inst
        if inst["DBInstanceStatus"] == "failed":
            raise AssertionError("DB instance entered status 'failed'")
        time.sleep(interval_s)
    raise AssertionError(f"DB instance {db_id} did not become available within {timeout_s}s")


def _register_instance_cleanup(ctx, rds, db_id):
    def _cleanup():
        deadline = time.monotonic() + 1200
        while time.monotonic() < deadline:
            try:
                inst = rds.describe_db_instances(DBInstanceIdentifier=db_id)["DBInstances"][0]
            except rds.exceptions.DBInstanceNotFoundFault:
                return
            if inst["DBInstanceStatus"] not in ("creating", "backing-up", "modifying"):
                break
            time.sleep(15)
        try:
            rds.delete_db_instance(DBInstanceIdentifier=db_id, SkipFinalSnapshot=True, DeleteAutomatedBackups=True)
        except rds.exceptions.DBInstanceNotFoundFault:
            pass

    ctx.on_cleanup(_cleanup)


def _retry_while_held(fn, *codes, timeout_s=600.0, interval_s=15.0):
    """Run a teardown delete, retrying while AWS refuses it because a dependent resource deleted just
    before it is still going away; after the deadline the last refusal is raised."""
    import time as _time

    from botocore.exceptions import ClientError

    deadline = _time.monotonic() + timeout_s
    while True:
        try:
            return fn()
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") not in codes or _time.monotonic() >= deadline:
                raise
        _time.sleep(interval_s)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
