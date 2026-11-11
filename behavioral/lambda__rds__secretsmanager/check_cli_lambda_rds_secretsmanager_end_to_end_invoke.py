"""cli-lambda-rds-secretsmanager-end-to-end-invoke."""

from __future__ import annotations

import json
import os
import random
import string
import subprocess
import tempfile
import time
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags
from fidelity_tests_runner import require_tools

CHECK = "cli-lambda-rds-secretsmanager-end-to-end-invoke"
GROUP = "cli-roundtrip"
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
    """A Lambda reads an Aurora Serverless v2 secret and runs CREATE TABLE, INSERT and SELECT
    through the Data API, returning the value it wrote."""
    require_tools("aws")

    rds = ctx.client("rds")
    db_name = "sim2realdb"
    admin_username = "dbadmin"
    admin_password = "".join(
        random.choices(string.ascii_letters + string.digits, k=24)
    )

    cluster_id = ctx.unique_name("sim2real-e2e-cluster-")
    subnet_group = _network_db_subnet_group(ctx, ctx.client('rds'))
    _run_aws(
        ctx,
        "rds",
        "create-db-cluster",
        "--db-subnet-group-name", subnet_group,
        "--db-cluster-identifier",
        cluster_id,
        "--engine",
        "aurora-mysql",
        "--master-username",
        admin_username,
        "--master-user-password",
        admin_password,
        "--database-name",
        db_name,
        "--enable-http-endpoint",
        "--serverless-v2-scaling-configuration",
        "MinCapacity=0.5,MaxCapacity=2",
        "--tags",
        "Key=sim2real,Value=true",
    )
    ctx.on_cleanup(lambda: _delete_cluster(ctx, cluster_id))

    instance_id = ctx.unique_name("sim2real-e2e-instance-")
    _run_aws(
        ctx,
        "rds",
        "create-db-instance",
        "--db-instance-identifier",
        instance_id,
        "--db-cluster-identifier",
        cluster_id,
        "--engine",
        "aurora-mysql",
        "--db-instance-class",
        "db.serverless",
        "--tags",
        "Key=sim2real,Value=true",
    )
    ctx.on_cleanup(lambda: _delete_instance(ctx, instance_id))

    _wait_instance_available(ctx, instance_id, timeout_s=1200.0)
    cluster_arn = rds.describe_db_clusters(DBClusterIdentifier=cluster_id)[
        "DBClusters"
    ][0]["DBClusterArn"]

    secretsmanager = ctx.client("secretsmanager")
    secret_name = ctx.unique_name("sim2real-e2e-secret-")
    secret = secretsmanager.create_secret(
        Name=secret_name,
        SecretString=json.dumps(
            {"username": admin_username, "password": admin_password}
        ),
        Tags=[{"Key": "sim2real", "Value": "true"}],
    )
    secret_arn = secret["ARN"]
    ctx.on_cleanup(
        lambda: secretsmanager.delete_secret(
            SecretId=secret_arn, ForceDeleteWithoutRecovery=True
        )
    )

    role_name = ctx.unique_name("sim2real-e2e-role-")
    _run_aws(
        ctx,
        "iam",
        "create-role",
        "--role-name",
        role_name,
        "--assume-role-policy-document",
        _lambda_trust_policy(),
        "--tags",
        "Key=sim2real,Value=true",
    )
    ctx.on_cleanup(lambda: _delete_role(ctx, role_name))
    _run_aws(
        ctx,
        "iam",
        "attach-role-policy",
        "--role-name",
        role_name,
        "--policy-arn",
        "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole",
    )
    data_api_policy = json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": [
                        "rds-data:ExecuteStatement",
                        "rds-data:BatchExecuteStatement",
                        "rds-data:BeginTransaction",
                        "rds-data:CommitTransaction",
                        "rds-data:RollbackTransaction",
                    ],
                    "Resource": cluster_arn,
                },
                {
                    "Effect": "Allow",
                    "Action": "secretsmanager:GetSecretValue",
                    "Resource": secret_arn,
                },
            ],
        }
    )
    _run_aws(
        ctx,
        "iam",
        "put-role-policy",
        "--role-name",
        role_name,
        "--policy-name",
        "data-api-access",
        "--policy-document",
        data_api_policy,
    )
    role_arn = _run_aws(ctx, "iam", "get-role", "--role-name", role_name)["Role"]["Arn"]

    handler_code = (
        "import json, os, boto3\n\n"
        "def handler(event, context):\n"
        "    secret_arn = os.environ['SECRET_ARN']\n"
        "    cluster_arn = os.environ['CLUSTER_ARN']\n"
        "    db_name = os.environ['DB_NAME']\n"
        "    sm = boto3.client('secretsmanager')\n"
        "    secret = sm.get_secret_value(SecretId=secret_arn)\n"
        "    secret_ok = 'SecretString' in secret\n"
        "    rds_data = boto3.client('rds-data')\n"
        "    common = dict(resourceArn=cluster_arn, secretArn=secret_arn, database=db_name)\n"
        "    rds_data.execute_statement(sql='CREATE TABLE IF NOT EXISTS sim2real_probe "
        "(id INT PRIMARY KEY, val VARCHAR(64))', **common)\n"
        "    rds_data.execute_statement(sql='DELETE FROM sim2real_probe', **common)\n"
        "    rds_data.execute_statement(\n"
        "        sql='INSERT INTO sim2real_probe (id, val) VALUES (:id, :val)',\n"
        "        parameters=[{'name': 'id', 'value': {'longValue': 1}},"
        " {'name': 'val', 'value': {'stringValue': 'hello-rds'}}],\n"
        "        **common)\n"
        "    result = rds_data.execute_statement(\n"
        "        sql='SELECT val FROM sim2real_probe WHERE id = 1',\n"
        "        formatRecordsAs='JSON', **common)\n"
        "    rows = json.loads(result['formattedRecords'])\n"
        "    return {'secret_ok': secret_ok, 'val': rows[0]['val'] if rows else None}\n"
    )
    zip_path = _write_zip(handler_code)
    function_name = ctx.unique_name("sim2real-e2e-fn-")

    _create_function_retrying(
        ctx,
        [
            "lambda",
            "create-function",
            "--function-name",
            function_name,
            "--runtime",
            "python3.12",
            "--role",
            role_arn,
            "--handler",
            "lambda_function.handler",
            "--zip-file",
            f"fileb://{zip_path}",
            "--timeout",
            "30",
            "--environment",
            json.dumps(
                {
                    "Variables": {
                        "SECRET_ARN": secret_arn,
                        "CLUSTER_ARN": cluster_arn,
                        "DB_NAME": db_name,
                    }
                }
            ),
            "--tags",
            "sim2real=true",
        ],
    )
    ctx.on_cleanup(
        lambda: ctx.client("lambda").delete_function(FunctionName=function_name)
    )
    _wait_function_active(ctx, function_name)

    body = _invoke_until_ok(ctx, function_name, timeout_s=180.0)
    assert body["secret_ok"] is True, (
        f"Lambda did not retrieve a SecretString from {secret_arn}: {body}"
    )
    assert body["val"] == "hello-rds", (
        f"round trip did not return the written value: {body}"
    )


def _run_shell(ctx, command, *, env_extra=None, timeout_s=60.0, check=True, cwd=None):
    ctx.verify_account_safety()
    env = ctx.subprocess_env()
    if env_extra:
        env.update(env_extra)
    result = subprocess.run(
        command,
        shell=isinstance(command, str),
        env=env,
        capture_output=True,
        text=True,
        timeout=timeout_s,
        cwd=cwd,
    )
    if check and result.returncode != 0:
        raise AssertionError(
            f"Command failed (rc={result.returncode}):\n  cmd: {command}\n"
            f"  stderr: {result.stderr[-500:]}"
        )
    return result


def _run_script(ctx, script: str, *, timeout_s=120.0, check=True, env_extra=None):
    with tempfile.NamedTemporaryFile(mode="w", suffix=".sh", delete=False) as f:
        f.write("#!/bin/bash\nset -euo pipefail\n")
        f.write(script)
        script_path = f.name
    try:
        os.chmod(script_path, 0o755)
        return _run_shell(
            ctx,
            ["bash", script_path],
            timeout_s=timeout_s,
            check=check,
            env_extra=env_extra,
        )
    finally:
        os.unlink(script_path)


def _run_aws(ctx, *args: str, timeout_s=30.0, check=True):
    proc = _run_shell(
        ctx, ["aws", "--output", "json", *args], timeout_s=timeout_s, check=check
    )
    if not proc.stdout.strip():
        return {}
    try:
        return json.loads(proc.stdout)
    except (json.JSONDecodeError, ValueError):
        return proc.stdout.strip()


def _lambda_trust_policy() -> str:
    return json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"Service": "lambda.amazonaws.com"},
                    "Action": "sts:AssumeRole",
                }
            ],
        }
    )


def _write_zip(handler_code: str) -> str:
    tmp_dir = tempfile.mkdtemp()
    src_path = os.path.join(tmp_dir, "lambda_function.py")
    with open(src_path, "w") as f:
        f.write(handler_code)
    zip_path = os.path.join(tmp_dir, "function.zip")
    with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.write(src_path, arcname="lambda_function.py")
    return zip_path


def _create_function_retrying(ctx, args, timeout_s=90.0):
    deadline = time.monotonic() + timeout_s
    last_err = None
    while time.monotonic() < deadline:
        proc = _run_shell(
            ctx, ["aws", "--output", "json", *args], check=False, timeout_s=30.0
        )
        if proc.returncode == 0:
            return json.loads(proc.stdout) if proc.stdout.strip() else {}
        if "cannot be assumed by Lambda" in proc.stderr:
            last_err = proc.stderr
            time.sleep(3)
            continue
        raise AssertionError(f"create-function failed: {proc.stderr[-500:]}")
    raise AssertionError(
        f"create-function kept failing on role assumption after {timeout_s}s: {last_err}"
    )


def _wait_function_active(ctx, function_name: str, timeout_s=90.0) -> None:
    lam = ctx.client("lambda")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        cfg = lam.get_function_configuration(FunctionName=function_name)
        if cfg.get("State") == "Active" and cfg.get("LastUpdateStatus") == "Successful":
            return
        if cfg.get("State") == "Failed":
            raise AssertionError(
                f"function {function_name} entered Failed state: {cfg.get('StateReason')}"
            )
        time.sleep(2)
    raise AssertionError(
        f"function {function_name} did not become Active within {timeout_s}s"
    )


def _wait_instance_available(
    ctx, instance_id: str, timeout_s=1200.0, interval_s=20.0
) -> None:
    rds = ctx.client("rds")
    deadline = time.monotonic() + timeout_s
    last_status = None
    while time.monotonic() < deadline:
        instances = rds.describe_db_instances(DBInstanceIdentifier=instance_id)[
            "DBInstances"
        ]
        last_status = instances[0]["DBInstanceStatus"]
        if last_status == "available":
            return
        if last_status in ("failed", "incompatible-parameters"):
            raise AssertionError(
                f"DB instance {instance_id} entered terminal bad status: {last_status}"
            )
        time.sleep(interval_s)
    raise AssertionError(
        f"DB instance {instance_id} never became available (last status: {last_status})"
    )


def _invoke_until_ok(ctx, function_name: str, timeout_s=180.0, interval_s=10.0):
    """The Data API can transiently report communications errors right after the cluster/instance
    first report 'available' while HTTP endpoint warms up; poll actual invocations to the real
    terminal condition (a successful round trip), not a status flag."""
    lam = ctx.client("lambda")
    deadline = time.monotonic() + timeout_s
    last_body = None
    last_error = None
    while time.monotonic() < deadline:
        resp = lam.invoke(FunctionName=function_name, Payload=b"{}")
        if resp.get("FunctionError") is not None:
            last_error = json.loads(resp["Payload"].read())
            time.sleep(interval_s)
            continue
        last_body = json.loads(resp["Payload"].read())
        if last_body.get("val") == "hello-rds":
            return last_body
        time.sleep(interval_s)
    raise AssertionError(
        f"round trip never succeeded within {timeout_s}s; last body={last_body} last_error={last_error}"
    )


def _delete_instance(ctx, instance_id: str, timeout_s=1200.0, interval_s=20.0) -> None:
    rds = ctx.client("rds")
    try:
        rds.delete_db_instance(DBInstanceIdentifier=instance_id)
    except rds.exceptions.DBInstanceNotFoundFault:
        return
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            rds.describe_db_instances(DBInstanceIdentifier=instance_id)
        except rds.exceptions.DBInstanceNotFoundFault:
            return
        time.sleep(interval_s)
    raise AssertionError(
        f"DB instance {instance_id} was not deleted within {timeout_s}s"
    )


def _delete_cluster(ctx, cluster_id: str, timeout_s=1200.0, interval_s=20.0) -> None:
    rds = ctx.client("rds")
    try:
        rds.delete_db_cluster(DBClusterIdentifier=cluster_id, SkipFinalSnapshot=True)
    except rds.exceptions.DBClusterNotFoundFault:
        return
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            rds.describe_db_clusters(DBClusterIdentifier=cluster_id)
        except rds.exceptions.DBClusterNotFoundFault:
            return
        time.sleep(interval_s)
    raise AssertionError(f"DB cluster {cluster_id} was not deleted within {timeout_s}s")


def _delete_role(ctx, role_name: str) -> None:
    iam = ctx.client("iam")
    for pol in iam.list_attached_role_policies(RoleName=role_name).get(
        "AttachedPolicies", []
    ):
        iam.detach_role_policy(RoleName=role_name, PolicyArn=pol["PolicyArn"])
    for pol_name in iam.list_role_policies(RoleName=role_name).get("PolicyNames", []):
        iam.delete_role_policy(RoleName=role_name, PolicyName=pol_name)
    iam.delete_role(RoleName=role_name)


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
