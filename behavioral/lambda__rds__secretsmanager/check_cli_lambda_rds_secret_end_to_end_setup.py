"""cli-lambda-rds-secret-end-to-end-setup."""

from __future__ import annotations

import io
import json
import os
import tempfile
import time
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags
from fidelity_tests_runner import require_tools

CHECK = "cli-lambda-rds-secret-end-to-end-setup"
GROUP = "cli-roundtrip"
SERVICES = ["lambda", "rds", "secretsmanager"]


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
    """A Lambda wired to an Aurora Serverless v2 cluster with the Data API and to a secret with
    its credentials reads the secret and returns 1 from a SQL query through ExecuteStatement."""
    require_tools("aws")

    secretsmanager = ctx.client("secretsmanager")
    rds = ctx.client("rds")
    lam = ctx.client("lambda")
    iam = ctx.client("iam")

    name = ctx.unique_name("sim2real-e2e-").lower()
    cluster_id = f"{name}-cluster"
    instance_id = f"{name}-inst"
    admin_user = "dbadmin"
    admin_pw = _random_password()
    db_name = "appdb"

    # --- 1. secret holding the admin credentials --------------------------------------------
    secret_payload = json.dumps({"username": admin_user, "password": admin_pw})
    secret = _run_aws(
        ctx,
        "secretsmanager",
        "create-secret",
        "--name",
        f"{name}-secret",
        "--secret-string",
        secret_payload,
        "--tags",
        json.dumps([{"Key": "sim2real-check", "Value": CHECK}]),
    )
    secret_arn = secret["ARN"]
    ctx.on_cleanup(
        lambda: secretsmanager.delete_secret(
            SecretId=secret_arn, ForceDeleteWithoutRecovery=True
        )
    )

    # --- 2. Aurora Serverless v2 PostgreSQL cluster + instance, Data API enabled ------------
    subnet_group = _network_db_subnet_group(ctx, ctx.client('rds'))
    _run_aws(
        ctx,
        "rds",
        "create-db-cluster",
        "--db-subnet-group-name", subnet_group,
        "--db-cluster-identifier",
        cluster_id,
        "--engine",
        "aurora-postgresql",
        "--master-username",
        admin_user,
        "--master-user-password",
        admin_pw,
        "--database-name",
        db_name,
        "--serverless-v2-scaling-configuration",
        "MinCapacity=0.5,MaxCapacity=1",
        "--enable-http-endpoint",
        "--tags",
        json.dumps([{"Key": "sim2real-check", "Value": CHECK}]),
    )

    def _delete_cluster():
        rds.delete_db_cluster(DBClusterIdentifier=cluster_id, SkipFinalSnapshot=True)
        _poll_until(
            lambda: _describe_cluster_status(rds, cluster_id) is None,
            lambda gone: gone is True,
            timeout_s=900,
            interval_s=15,
        )

    ctx.on_cleanup(_delete_cluster)
    cluster_desc = rds.describe_db_clusters(DBClusterIdentifier=cluster_id)[
        "DBClusters"
    ][0]
    cluster_arn = cluster_desc["DBClusterArn"]

    _run_aws(
        ctx,
        "rds",
        "create-db-instance",
        "--db-instance-identifier",
        instance_id,
        "--db-cluster-identifier",
        cluster_id,
        "--engine",
        "aurora-postgresql",
        "--db-instance-class",
        "db.serverless",
        "--tags",
        json.dumps([{"Key": "sim2real-check", "Value": CHECK}]),
    )

    def _delete_instance():
        rds.delete_db_instance(DBInstanceIdentifier=instance_id, SkipFinalSnapshot=True)
        _poll_until(
            lambda: _describe_instance_status(rds, instance_id) is None,
            lambda gone: gone is True,
            timeout_s=900,
            interval_s=15,
        )

    ctx.on_cleanup(_delete_instance)

    _poll_until(
        lambda: _describe_cluster_status(rds, cluster_id),
        lambda status: status == "available",
        timeout_s=900,
        interval_s=15,
    )
    _poll_until(
        lambda: _describe_instance_status(rds, instance_id),
        lambda status: status == "available",
        timeout_s=900,
        interval_s=15,
    )

    # --- 3. IAM role + Lambda function wired to both the secret and the Data API ------------
    role_name = f"{name}-role"
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
    policy_doc = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": "secretsmanager:GetSecretValue",
                "Resource": secret_arn,
            },
            {
                "Effect": "Allow",
                "Action": [
                    "rds-data:ExecuteStatement",
                    "rds-data:BatchExecuteStatement",
                ],
                "Resource": cluster_arn,
            },
            {
                "Effect": "Allow",
                "Action": [
                    "logs:CreateLogGroup",
                    "logs:CreateLogStream",
                    "logs:PutLogEvents",
                ],
                "Resource": "*",
            },
        ],
    }
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName="inline-e2e",
        PolicyDocument=json.dumps(policy_doc),
    )
    ctx.on_cleanup(
        lambda: iam.delete_role_policy(RoleName=role_name, PolicyName="inline-e2e")
    )

    handler_code = (
        "import boto3\n"
        "import os\n\n"
        "def handler(event, context):\n"
        "    sm = boto3.client('secretsmanager')\n"
        "    secret_resp = sm.get_secret_value(SecretId=os.environ['SECRET_ARN'])\n"
        "    secret_ok = bool(secret_resp.get('SecretString'))\n"
        "    rds_data = boto3.client('rds-data')\n"
        "    query_resp = rds_data.execute_statement(\n"
        "        resourceArn=os.environ['CLUSTER_ARN'],\n"
        "        secretArn=os.environ['SECRET_ARN'],\n"
        "        database=os.environ['DB_NAME'],\n"
        "        sql='SELECT 1 AS one',\n"
        "    )\n"
        "    one_value = query_resp['records'][0][0]['longValue']\n"
        "    return {'secret_ok': secret_ok, 'query_result': one_value}\n"
    )
    zip_path = _write_zip(handler_code)
    ctx.on_cleanup(lambda: os.path.exists(zip_path) and os.unlink(zip_path))

    fn_name = f"{name}-fn"
    env_arg = json.dumps(
        {
            "Variables": {
                "SECRET_ARN": secret_arn,
                "CLUSTER_ARN": cluster_arn,
                "DB_NAME": db_name,
            }
        }
    )
    _run_aws_with_retry(
        ctx,
        "lambda",
        "create-function",
        "--function-name",
        fn_name,
        "--runtime",
        "python3.12",
        "--handler",
        "index.handler",
        "--role",
        role_arn,
        "--zip-file",
        f"fileb://{zip_path}",
        "--environment",
        env_arg,
        "--timeout",
        "30",
        "--tags",
        json.dumps({"sim2real-check": CHECK}),
        retry_s=90,
    )
    ctx.on_cleanup(lambda: lam.delete_function(FunctionName=fn_name))

    _poll_until(
        lambda: lam.get_function_configuration(FunctionName=fn_name),
        lambda cfg: (
            cfg["State"] == "Active" and cfg["LastUpdateStatus"] == "Successful"
        ),
        timeout_s=120,
        interval_s=5,
    )

    payload = _invoke_until_ok(lam, fn_name, timeout_s=180.0, interval_s=10.0)
    assert payload["secret_ok"] is True, (
        f"lambda did not read a non-empty secret: {payload}"
    )
    assert payload["query_result"] == 1, (
        f"rds-data ExecuteStatement through the Lambda did not return 1 for 'SELECT 1': {payload}"
    )


import subprocess


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


def _run_aws(ctx, *args: str, timeout_s=60.0, check=True):
    proc = _run_shell(
        ctx, ["aws", "--output", "json", *args], timeout_s=timeout_s, check=check
    )
    if not proc.stdout.strip():
        return {}
    try:
        return json.loads(proc.stdout)
    except (json.JSONDecodeError, ValueError):
        return proc.stdout.strip()


def _run_aws_with_retry(ctx, *args: str, retry_s=90.0, interval_s=5.0, timeout_s=60.0):
    """create-function/create-db-proxy can fail transiently for ~60-90s while a freshly
    created IAM role has not yet propagated. Retry until success or the window elapses."""
    deadline = time.monotonic() + retry_s
    last_err = None
    while time.monotonic() < deadline:
        proc = _run_shell(
            ctx, ["aws", "--output", "json", *args], timeout_s=timeout_s, check=False
        )
        if proc.returncode == 0:
            if not proc.stdout.strip():
                return {}
            try:
                return json.loads(proc.stdout)
            except (json.JSONDecodeError, ValueError):
                return proc.stdout.strip()
        last_err = proc.stderr
        time.sleep(interval_s)
    raise AssertionError(
        f"command never succeeded within {retry_s}s: {args}\nlast error: {last_err}"
    )


def _invoke_until_ok(lam, fn_name: str, *, timeout_s=180.0, interval_s=10.0) -> dict:
    """The Data API's HTTP endpoint can transiently error for a short window right after the
    cluster/instance first report 'available'; poll the real terminal condition (a clean
    invocation), not the availability status flag."""
    deadline = time.monotonic() + timeout_s
    last_error = None
    while time.monotonic() < deadline:
        resp = lam.invoke(FunctionName=fn_name, Payload=b"{}")
        raw = resp["Payload"].read()
        if "FunctionError" not in resp:
            return json.loads(raw)
        last_error = raw.decode("utf-8", "replace") if isinstance(raw, bytes) else raw
        time.sleep(interval_s)
    raise AssertionError(
        f"lambda invoke never succeeded within {timeout_s}s "
        f"(last FunctionError body: {last_error})"
    )


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=5.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(
        f"condition never satisfied within {timeout_s}s (last value: {last!r})"
    )


def _describe_cluster_status(rds, cluster_id) -> str | None:
    try:
        return rds.describe_db_clusters(DBClusterIdentifier=cluster_id)["DBClusters"][
            0
        ]["Status"]
    except rds.exceptions.DBClusterNotFoundFault:
        return None


def _describe_instance_status(rds, instance_id) -> str | None:
    try:
        return rds.describe_db_instances(DBInstanceIdentifier=instance_id)[
            "DBInstances"
        ][0]["DBInstanceStatus"]
    except rds.exceptions.DBInstanceNotFoundFault:
        return None


def _random_password(length: int = 24) -> str:
    import secrets
    import string

    alphabet = string.ascii_letters + string.digits
    return "Aa1" + "".join(secrets.choice(alphabet) for _ in range(length - 3))


def _write_zip(handler_code: str) -> str:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("index.py", handler_code)
    with tempfile.NamedTemporaryFile(suffix=".zip", delete=False) as f:
        f.write(buf.getvalue())
        return f.name


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
