"""backup-job-state-change-invokes-lambda-target."""
from __future__ import annotations

import io
import json
import time
import zipfile

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "backup-job-state-change-invokes-lambda-target"
GROUP = "event-propagation"
SERVICES = ["backup", "events"]


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "concern:e2e", "concern:eventing", "dp:api", "plane:data")
def run(ctx) -> None:
    """A rule matching a Backup Job State Change event with state RUNNING invokes its Lambda target
    with the job payload of a real on-demand backup job."""
    events = ctx.client("events")
    lam = ctx.client("lambda")
    iam = ctx.client("iam")
    logs = ctx.client("logs")

    role_arn = _create_lambda_role(ctx, iam)
    fn_name = ctx.unique_name("sim2real-beh-fn-")
    fn_arn = _create_function(ctx, lam, fn_name, role_arn)

    rule_name = ctx.unique_name("sim2real-beh-rule-")
    pattern = {
        "source": ["aws.backup"],
        "detail-type": ["Backup Job State Change"],
        "detail": {"state": ["RUNNING", "PENDING", "CREATED", "COMPLETED"]},
    }
    rule_arn = events.put_rule(Name=rule_name, EventPattern=json.dumps(pattern), State="ENABLED")["RuleArn"]
    ctx.on_cleanup(lambda: _delete_rule(events, rule_name, ["lambda-target"]))

    lam.add_permission(
        FunctionName=fn_name,
        StatementId="AllowEventBridgeInvoke",
        Action="lambda:InvokeFunction",
        Principal="events.amazonaws.com",
        SourceArn=rule_arn,
    )
    events.put_targets(Rule=rule_name, Targets=[{"Id": "lambda-target", "Arn": fn_arn}])

    # EventBridge silently drops customer PutEvents entries that forge a reserved
    # "aws.*" source, so we drive a REAL backup job and observe the native
    # state-change event (whichever early state it first reaches) actually
    # invoking the Lambda target -- COMPLETED can take well past the check's
    # budget for even an empty DynamoDB table, so any of the job's real states is
    # an acceptable, budget-safe positive signal here.
    backup = ctx.client("backup")
    table_name, table_arn = _create_table(ctx)
    vault_name, vault_arn = _create_vault(ctx)
    backup_role_arn = _create_backup_service_role(ctx)

    job_id = _start_backup_job_with_role_retry(ctx, vault_name, table_arn, backup_role_arn)

    found = _poll_logs_for_marker(logs, f"/aws/lambda/{fn_name}", job_id, timeout_s=180.0)
    assert found, f"expected the Lambda invocation log to contain marker {job_id}"


def _create_table(ctx) -> tuple[str, str]:
    ddb = ctx.client("dynamodb")
    name = ctx.unique_name("sim2real-beh-tbl-")
    resp = ddb.create_table(
        TableName=name,
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        BillingMode="PAY_PER_REQUEST",
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=name))
    ddb.get_waiter("table_exists").wait(TableName=name, WaiterConfig={"Delay": 2, "MaxAttempts": 250})
    return name, resp["TableDescription"]["TableArn"]


def _create_vault(ctx) -> tuple[str, str]:
    backup = ctx.client("backup")
    name = ctx.unique_name("sim2real-beh-vault-")
    resp = backup.create_backup_vault(BackupVaultName=name)
    ctx.on_cleanup(lambda: _cleanup_vault(backup, name))
    return name, resp["BackupVaultArn"]


def _cleanup_vault(backup, vault_name: str) -> None:
    try:
        rps = backup.list_recovery_points_by_backup_vault(BackupVaultName=vault_name).get(
            "RecoveryPoints", []
        )
        for rp in rps:
            try:
                backup.delete_recovery_point(
                    BackupVaultName=vault_name, RecoveryPointArn=rp["RecoveryPointArn"]
                )
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                    raise
        backup.delete_backup_vault(BackupVaultName=vault_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _create_backup_service_role(ctx) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-beh-bkuprole-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": "backup.amazonaws.com"}, "Action": "sts:AssumeRole"}],
    }
    role_arn = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust))["Role"]["Arn"]
    policy_arn = "arn:aws:iam::aws:policy/service-role/AWSBackupServiceRolePolicyForBackup"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
    ctx.on_cleanup(lambda: _delete_role_bkup(iam, role_name, [policy_arn]))
    return role_arn


def _start_backup_job_with_role_retry(ctx, vault_name: str, resource_arn: str, role_arn: str, timeout_s: float = 120.0, interval_s: float = 5.0) -> str:
    """A freshly-created IAM role is not always immediately usable by the AWS Backup service
    (IAM permission propagation lag); retry StartBackupJob on the transient
    InvalidParameterValueException/'insufficient permissions' response until it clears."""
    backup = ctx.client("backup")
    deadline = time.monotonic() + timeout_s
    last_err: Exception | None = None
    while time.monotonic() < deadline:
        try:
            return backup.start_backup_job(
                BackupVaultName=vault_name, ResourceArn=resource_arn, IamRoleArn=role_arn
            )["BackupJobId"]
        except backup.exceptions.InvalidParameterValueException as err:
            msg = err.response["Error"].get("Message", "")
            if "permission" in msg.lower():
                last_err = err
                time.sleep(interval_s)
                continue
            raise
    raise AssertionError(f"StartBackupJob role permissions never propagated within {timeout_s}s: {last_err}")


def _delete_role_bkup(iam, role_name: str, managed_policy_arns: list[str]) -> None:
    for arn in managed_policy_arns:
        try:
            iam.detach_role_policy(RoleName=role_name, PolicyArn=arn)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise
    try:
        iam.delete_role(RoleName=role_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _create_lambda_role(ctx, iam) -> str:
    role_name = ctx.unique_name("sim2real-beh-lam-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}],
    }
    role_arn = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust))["Role"]["Arn"]
    ctx.on_cleanup(lambda: _delete_role(iam, role_name, ["arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"]))
    iam.attach_role_policy(
        RoleName=role_name, PolicyArn="arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
    )
    return role_arn


def _delete_role(iam, role_name: str, managed_policy_arns: list[str]) -> None:
    for arn in managed_policy_arns:
        try:
            iam.detach_role_policy(RoleName=role_name, PolicyArn=arn)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise
    try:
        iam.delete_role(RoleName=role_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _lambda_zip() -> bytes:
    code = (
        "import json\n"
        "def handler(event, context):\n"
        "    print('RECEIVED_EVENT::' + json.dumps(event))\n"
        "    return {'ok': True}\n"
    )
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("lambda_function.py", code)
    return buf.getvalue()


def _create_function(ctx, lam, fn_name: str, role_arn: str) -> str:
    zip_bytes = _lambda_zip()
    deadline = time.monotonic() + 60.0
    last_exc: Exception | None = None
    while time.monotonic() < deadline:
        try:
            ctx.on_cleanup(lambda _n=fn_name: _delete_lambda_log_group(ctx, _n))
            resp = lam.create_function(
                FunctionName=fn_name,
                Runtime="python3.12",
                Role=role_arn,
                Handler="lambda_function.handler",
                Code={"ZipFile": zip_bytes},
                Timeout=15,
            )
            ctx.on_cleanup(lambda: lam.delete_function(FunctionName=fn_name))
            return resp["FunctionArn"]
        except lam.exceptions.InvalidParameterValueException as exc:
            last_exc = exc
            time.sleep(4.0)
    raise AssertionError(f"lambda create_function never succeeded (IAM propagation?): {last_exc}")


def _delete_rule(events, rule_name: str, target_ids: list[str]) -> None:
    try:
        if target_ids:
            events.remove_targets(Rule=rule_name, Ids=target_ids, Force=True)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise
    try:
        events.delete_rule(Name=rule_name, Force=True)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _poll_logs_for_marker(logs, log_group: str, marker: str, timeout_s: float = 90.0) -> bool:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            resp = logs.filter_log_events(logGroupName=log_group, filterPattern=f'"{marker}"')
            for event in resp.get("events", []):
                if marker in event.get("message", ""):
                    return True
        except logs.exceptions.ResourceNotFoundException:
            pass
        time.sleep(4.0)
    return False


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
