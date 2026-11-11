"""lambda-rds-proxy-missing-permission-denied."""
from __future__ import annotations

import io
import json
import os
import time
import zipfile

from behavioral_harness import tags
import secrets

CHECK = "lambda-rds-proxy-missing-permission-denied"
GROUP = "permission-boundary"
SERVICES = ["lambda", "rds", "secretsmanager"]

_HANDLER = """
import boto3
import ssl as ssl_lib
import pymysql

def handler(event, context):
    client = boto3.client("rds", region_name=event["region"])
    token = client.generate_db_auth_token(
        DBHostname=event["proxy_endpoint"], Port=int(event["port"]), DBUsername=event["user"],
    )
    ctx = ssl_lib.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl_lib.CERT_NONE
    try:
        conn = pymysql.connect(
            host=event["proxy_endpoint"], port=int(event["port"]), user=event["user"], password=token,
            ssl={"context": ctx}, connect_timeout=15,
            auth_plugin_map={"mysql_clear_password": None},
        )
    except pymysql.err.OperationalError as exc:
        code = exc.args[0] if exc.args else None
        return {"ok": False, "mysql_error_code": code}
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT 1")
            row = cur.fetchone()
        return {"ok": True, "value": row[0]}
    finally:
        conn.close()
"""


@tags("axis:rejection", "cap:c3", "cap:c4", "cap:c7", "concern:data-plane", "concern:e2e", "concern:negative-classes", "dp:api", "dp:native", "plane:data")
def run(ctx) -> None:
    """Through an IAM-auth RDS Proxy, a Lambda role lacking rds-db:connect on the dbuser ARN gets
    MySQL access-denied with no query run, while a role granted that ARN connects and queries."""
    import pymysql  # noqa: F401  (vendored into the Lambda deployment package)

    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]
    ec2 = ctx.client("ec2")
    _vpc_id, subnet_ids, sg_id = _default_vpc_subnets(ctx, ec2)

    rds = ctx.client("rds")
    secretsmanager = ctx.client("secretsmanager")

    subnet_group = _create_subnet_group(ctx, rds, subnet_ids)
    db_id = ctx.unique_name("sim2real-rds-pxiam-")
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
        BackupRetentionPeriod=0,
        Tags=[{"Key": "sim2real", "Value": "true"}],
    )
    _register_instance_cleanup(ctx, rds, db_id)
    _wait_instance_available(rds, db_id)

    secret_arn = _create_db_secret(ctx, secretsmanager, "admin", admin_password)
    proxy_role_arn = _create_proxy_role(ctx, secret_arn)

    proxy_name = ctx.unique_name("sim2real-proxy-iam-")
    _create_db_proxy(
        ctx, rds, proxy_name, proxy_role_arn, secret_arn, subnet_ids, sg_id,
        iam_auth="REQUIRED", require_tls=True,
    )
    rds.register_db_proxy_targets(DBProxyName=proxy_name, DBInstanceIdentifiers=[db_id])
    _wait_proxy_available(rds, proxy_name)
    _wait_target_available(rds, proxy_name)
    proxy = rds.describe_db_proxies(DBProxyName=proxy_name)["DBProxies"][0]
    proxy_endpoint, proxy_port = proxy["Endpoint"], 3306
    proxy_id = proxy["DBProxyArn"].rsplit(":", 1)[-1]

    connect_arn = f"arn:aws:rds-db:{ctx.region}:{account_id}:dbuser:{proxy_id}/admin"

    allowed_role_arn, _ = _create_lambda_role(
        ctx, statements=[{"Effect": "Allow", "Action": "rds-db:connect", "Resource": connect_arn}], vpc=True
    )
    denied_role_arn, _ = _create_lambda_role(ctx, statements=[], vpc=True)

    zip_bytes = _build_lambda_zip(_HANDLER)
    vpc_config = {"SubnetIds": subnet_ids, "SecurityGroupIds": [sg_id]}
    allowed_fn = _create_function(ctx, allowed_role_arn, zip_bytes, timeout=30, vpc_config=vpc_config)
    denied_fn = _create_function(ctx, denied_role_arn, zip_bytes, timeout=30, vpc_config=vpc_config)

    payload = {"proxy_endpoint": proxy_endpoint, "port": proxy_port, "user": "admin", "region": ctx.region}

    # positive control: the role granted rds-db:connect on this exact dbuser ARN can connect and query
    ok_result = _invoke(ctx, allowed_fn, payload)
    assert ok_result["ok"] is True, (
        f"role granted rds-db:connect on {connect_arn} must authenticate through the IAM-auth "
        f"proxy and run a query; got {ok_result!r}"
    )
    assert ok_result["value"] == 1, f"expected SELECT 1 to return 1, got {ok_result!r}"

    # negative: no rds-db:connect grant at all -> authentication is refused and no query ever runs
    denied_result = _invoke(ctx, denied_fn, payload)
    assert denied_result["ok"] is False, (
        f"role with no rds-db:connect grant on {connect_arn} must be refused by the IAM-auth "
        f"proxy, not reach a query; got {denied_result!r}"
    )
    assert denied_result["mysql_error_code"] == 1045, (
        "role with no rds-db:connect grant must fail with MySQL access-denied (1045), not some "
        f"other error; got {denied_result!r}"
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

        raise AssertionError("no shared network VPC is available in this account/region to place the RDS proxy and Lambdas")
    vpc_id = vpcs[0]["VpcId"]
    subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}])["Subnets"]
    if len(subnets) < 2:

        raise AssertionError("shared network has fewer than 2 subnets; RDS Proxy requires at least 2 subnets")
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


def _create_db_secret(ctx, secretsmanager, username, password):
    name = ctx.unique_name("sim2real-dbsecret-")
    secret = secretsmanager.create_secret(
        Name=name, SecretString=json.dumps({"username": username, "password": password})
    )
    ctx.on_cleanup(lambda: secretsmanager.delete_secret(SecretId=name, ForceDeleteWithoutRecovery=True))
    return secret["ARN"]


def _create_proxy_role(ctx, secret_arn):
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-proxyrole-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": "rds.amazonaws.com"}, "Action": "sts:AssumeRole"}],
    }
    role_arn = iam.create_role(RoleName=name, AssumeRolePolicyDocument=json.dumps(trust))["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=name))
    policy = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Action": ["secretsmanager:GetSecretValue"], "Resource": secret_arn}],
    }
    iam.put_role_policy(RoleName=name, PolicyName="secrets-access", PolicyDocument=json.dumps(policy))
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=name, PolicyName="secrets-access"))
    return role_arn


def _create_db_proxy(ctx, rds, name, role_arn, secret_arn, subnet_ids, sg_id, iam_auth="DISABLED", require_tls=False):
    # IAM role propagation: retry the create on its documented error for up to 120 s.
    deadline = time.monotonic() + 120
    left = ctx.time_left()
    if left is not None:
        deadline = min(deadline, time.monotonic() + max(1.0, left - 5.0))
    while True:
        try:
            rds.create_db_proxy(
                DBProxyName=name,
                EngineFamily="MYSQL",
                Auth=[{"AuthScheme": "SECRETS", "SecretArn": secret_arn, "IAMAuth": iam_auth}],
                RoleArn=role_arn,
                VpcSubnetIds=subnet_ids,
                VpcSecurityGroupIds=[sg_id],
                RequireTLS=require_tls,
            )
            break
        except rds.exceptions.InvalidParameterValueException:
            if time.monotonic() >= deadline:
                raise AssertionError("failed to create db proxy after retries (IAM role propagation)")
            time.sleep(2)
    ctx.on_cleanup(lambda: rds.delete_db_proxy(DBProxyName=name))


def _wait_proxy_available(rds, name, timeout_s=900, interval_s=15):
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        proxy = rds.describe_db_proxies(DBProxyName=name)["DBProxies"][0]
        if proxy["Status"] == "available":
            return proxy
        time.sleep(interval_s)
    raise AssertionError(f"proxy {name} did not become available within {timeout_s}s")


def _wait_target_available(rds, name, timeout_s=600, interval_s=15):
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        targets = rds.describe_db_proxy_targets(DBProxyName=name)["Targets"]
        if targets and targets[0]["TargetHealth"]["State"] == "AVAILABLE":
            return
        time.sleep(interval_s)
    raise AssertionError(f"proxy target for {name} never became available within {timeout_s}s")


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
