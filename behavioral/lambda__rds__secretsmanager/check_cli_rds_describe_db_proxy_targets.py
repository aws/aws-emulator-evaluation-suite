"""cli-rds-describe-db-proxy-targets."""
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

CHECK = "cli-rds-describe-db-proxy-targets"
GROUP = "cli-roundtrip"
SERVICES = ["lambda", "rds", "secretsmanager"]

_MANAGED_TAG_KEY = "sim2real:managed"
_PREFIX = "sim2real-proxy"


def _mgmt_tags_kv() -> list[dict[str, str]]:
    return [{"Key": _MANAGED_TAG_KEY, "Value": "true"}, {"Key": "sim2real:prefix", "Value": _PREFIX}]


def _mgmt_tags_cli_args() -> list[str]:
    return ["--tags", f"Key={_MANAGED_TAG_KEY},Value=true", f"Key=sim2real:prefix,Value={_PREFIX}"]


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "concern:e2e", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """The CLI creates an RDS Proxy with Secrets Manager auth and registers a DB instance target; a
    Lambda then confirms via the SDK the proxy's secret-based auth wiring and that the target
    reaches AVAILABLE.
    """
    require_tools("aws")

    ec2 = ctx.client("ec2")
    rds = ctx.client("rds")
    secretsmanager = ctx.client("secretsmanager")
    lam = ctx.client("lambda")
    iam = ctx.client("iam")

    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if not vpcs:
        raise AssertionError("no shared network VPC in this account/region to host the RDS Proxy")
    vpc_id = vpcs[0]["VpcId"]
    subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}])["Subnets"]
    azs = {s["AvailabilityZone"] for s in subnets}
    if len(azs) < 2:
        raise AssertionError("shared network does not span 2+ AZs, required for an RDS Proxy")
    subnet_ids = list({s["SubnetId"]: s["AvailabilityZone"] for s in subnets}.keys())[:3]
    default_sg = ec2.describe_security_groups(
        Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "group-name", "Values": ["default"]}]
    )["SecurityGroups"][0]["GroupId"]

    name = ctx.unique_name("sim2real-proxy-").lower()
    instance_id = f"{name}-db"
    master_user = "dbadmin"
    master_pw = _random_password()

    secret = secretsmanager.create_secret(
        Name=f"{name}-secret",
        SecretString=json.dumps({"username": master_user, "password": master_pw}),
        Tags=_mgmt_tags_kv(),
    )
    secret_arn = secret["ARN"]
    ctx.on_cleanup(lambda: secretsmanager.delete_secret(
        SecretId=secret_arn, ForceDeleteWithoutRecovery=True
    ))

    subnet_group = _network_db_subnet_group(ctx, ctx.client('rds'))
    _run_aws(
        ctx, "rds", "create-db-instance",
        "--db-subnet-group-name", subnet_group,
        "--db-instance-identifier", instance_id,
        "--engine", "mysql",
        "--db-instance-class", "db.t3.micro",
        "--allocated-storage", "20",
        "--master-username", master_user,
        "--master-user-password", master_pw,
        "--vpc-security-group-ids", default_sg,
        "--no-publicly-accessible",
        "--no-multi-az",
        *_mgmt_tags_cli_args(),
    )

    # Fire the delete without polling: RDS takes far longer than the 60 s cleanup budget to remove
    # an instance, and a poll here would starve the cleanups that run after it (LIFO).
    ctx.on_cleanup(lambda: rds.delete_db_instance(
        DBInstanceIdentifier=instance_id, SkipFinalSnapshot=True
    ))
    _poll_until(
        lambda: _describe_instance_status(rds, instance_id),
        lambda status: status == "available",
        timeout_s=_budget_s(ctx, 900), interval_s=2, ctx=ctx,
    )

    proxy_role_name = f"{name}-proxy-role"
    trust = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"Service": "rds.amazonaws.com"},
            "Action": "sts:AssumeRole",
        }],
    }
    proxy_role = iam.create_role(
        RoleName=proxy_role_name, AssumeRolePolicyDocument=json.dumps(trust), Tags=_mgmt_tags_kv()
    )
    proxy_role_arn = proxy_role["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=proxy_role_name))
    proxy_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Action": "secretsmanager:GetSecretValue", "Resource": secret_arn},
        ],
    }
    iam.put_role_policy(
        RoleName=proxy_role_name, PolicyName="inline-proxy", PolicyDocument=json.dumps(proxy_policy)
    )
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=proxy_role_name, PolicyName="inline-proxy"))

    proxy_name = f"{name}-proxy"
    auth_cfg = json.dumps([{"AuthScheme": "SECRETS", "SecretArn": secret_arn, "IAMAuth": "DISABLED"}])
    _run_aws_with_retry(
        ctx,
        "rds", "create-db-proxy",
        "--db-proxy-name", proxy_name,
        "--engine-family", "MYSQL",
        "--auth", auth_cfg,
        "--role-arn", proxy_role_arn,
        "--vpc-subnet-ids", *subnet_ids,
        "--vpc-security-group-ids", default_sg,
        *_mgmt_tags_cli_args(),
        retry_s=90,
    )
    ctx.on_cleanup(lambda: rds.delete_db_proxy(DBProxyName=proxy_name))
    _poll_until(
        lambda: rds.describe_db_proxies(DBProxyName=proxy_name)["DBProxies"][0]["Status"],
        lambda status: status == "available",
        timeout_s=_budget_s(ctx, 600), interval_s=2, ctx=ctx,
    )

    _run_aws(
        ctx, "rds", "register-db-proxy-targets",
        "--db-proxy-name", proxy_name,
        "--db-instance-identifiers", instance_id,
    )

    def _target_health():
        targets = rds.describe_db_proxy_targets(DBProxyName=proxy_name)["Targets"]
        return targets[0] if targets else None

    # TargetHealth.State can sit at UNAVAILABLE/PENDING_PROXY_CAPACITY while the proxy is
    # still scaling to its desired capacity -- that is not a terminal state, so the poll must
    # not stop there. Only AVAILABLE (success) or the deadline (raised by _poll_until) ends it.
    target = _poll_until(
        _target_health,
        lambda t: t is not None and t["TargetHealth"]["State"] == "AVAILABLE",
        timeout_s=_budget_s(ctx, 1200), interval_s=2, ctx=ctx,
    )
    assert target["Type"] == "RDS_INSTANCE", f"expected Type=RDS_INSTANCE, got {target['Type']!r}"
    assert target["RdsResourceId"] == instance_id, (
        f"expected RdsResourceId={instance_id!r}, got {target['RdsResourceId']!r}"
    )
    assert target["TargetHealth"]["State"] == "AVAILABLE", (
        f"expected TargetHealth.State=AVAILABLE, got {target['TargetHealth']!r}"
    )

    lambda_role_name = f"{name}-verifier-role"
    lambda_trust = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"Service": "lambda.amazonaws.com"},
            "Action": "sts:AssumeRole",
        }],
    }
    lambda_role = iam.create_role(
        RoleName=lambda_role_name, AssumeRolePolicyDocument=json.dumps(lambda_trust),
        Tags=_mgmt_tags_kv(),
    )
    lambda_role_arn = lambda_role["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=lambda_role_name))
    lambda_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Action": [
                "rds:DescribeDBProxies", "rds:DescribeDBProxyTargets",
            ], "Resource": "*"},
            {"Effect": "Allow", "Action": [
                "logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents",
            ], "Resource": "*"},
        ],
    }
    iam.put_role_policy(
        RoleName=lambda_role_name, PolicyName="inline-verifier", PolicyDocument=json.dumps(lambda_policy)
    )
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=lambda_role_name, PolicyName="inline-verifier"))

    handler_code = (
        "import boto3\n"
        "import os\n\n"
        "def handler(event, context):\n"
        "    rds = boto3.client('rds')\n"
        "    proxy = rds.describe_db_proxies(DBProxyName=os.environ['PROXY_NAME'])['DBProxies'][0]\n"
        "    targets = rds.describe_db_proxy_targets(DBProxyName=os.environ['PROXY_NAME'])['Targets']\n"
        "    return {\n"
        "        'secret_arn': proxy['Auth'][0]['SecretArn'],\n"
        "        'target_state': targets[0]['TargetHealth']['State'] if targets else None,\n"
        "    }\n"
    )
    zip_path = _write_zip(handler_code)
    ctx.on_cleanup(lambda: os.path.exists(zip_path) and os.unlink(zip_path))

    fn_name = f"{name}-verifier"
    _run_aws_with_retry(
        ctx,
        "lambda", "create-function",
        "--function-name", fn_name,
        "--runtime", "python3.12",
        "--handler", "index.handler",
        "--role", lambda_role_arn,
        "--zip-file", f"fileb://{zip_path}",
        "--environment", json.dumps({"Variables": {"PROXY_NAME": proxy_name}}),
        "--timeout", "30",
        "--tags", f"{_MANAGED_TAG_KEY}=true,sim2real:prefix={_PREFIX}",
        retry_s=90,
    )
    ctx.on_cleanup(lambda: lam.delete_function(FunctionName=fn_name))
    _poll_until(
        lambda: lam.get_function_configuration(FunctionName=fn_name),
        lambda cfg: cfg["State"] == "Active" and cfg["LastUpdateStatus"] == "Successful",
        timeout_s=_budget_s(ctx, 120), interval_s=1, ctx=ctx,
    )

    resp = lam.invoke(FunctionName=fn_name, Payload=b"{}")
    assert "FunctionError" not in resp, f"invoke failed: {resp.get('FunctionError')}"
    payload = json.loads(resp["Payload"].read())
    assert payload["secret_arn"] == secret_arn, (
        f"expected Lambda-observed secret_arn={secret_arn!r}, got {payload['secret_arn']!r}"
    )
    assert payload["target_state"] == "AVAILABLE", (
        f"expected Lambda-observed target_state=AVAILABLE, got {payload['target_state']!r}"
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


def _run_aws_with_retry(ctx, *args: str, retry_s=90.0, interval_s=2.0, timeout_s=60.0):
    retry_s = _budget_s(ctx, retry_s)
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
    if _budget_spent(ctx):
        raise TimeoutError(f"command {args[:2]} to succeed: the run budget ended first; not graded")
    raise AssertionError(f"command never succeeded within {retry_s}s: {args}\nlast error: {last_err}")


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0, ctx=None):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    if ctx is not None and _budget_spent(ctx):
        raise TimeoutError(f"RDS proxy condition (last value: {last!r}): the run budget ended first; not graded")
    raise AssertionError(f"condition never satisfied within {timeout_s}s (last value: {last!r})")


def _describe_instance_status(rds, instance_id) -> str | None:
    try:
        return rds.describe_db_instances(DBInstanceIdentifier=instance_id)["DBInstances"][0][
            "DBInstanceStatus"
        ]
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
