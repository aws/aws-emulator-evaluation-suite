"""eventbridge-rule-triggers-startbackupjob-via-target-role."""
from __future__ import annotations

import datetime as dt
import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "eventbridge-rule-triggers-startbackupjob-via-target-role"
GROUP = "permission-boundary"
SERVICES = ["backup", "events"]


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "concern:e2e", "concern:eventing", "dp:api", "plane:data")
def run(ctx) -> None:
    """A rule invokes its Step Functions target through a role trusted by events.amazonaws.com, the
    state machine's SDK task calls backup:StartBackupJob with that role, and a real backup job is
    created for the resource."""
    events = ctx.client("events")
    sfn = ctx.client("stepfunctions")
    backup = ctx.client("backup")

    table_name, table_arn = _create_table(ctx)
    vault_name, vault_arn = _create_vault(ctx)
    backup_svc_role_arn = _create_backup_service_role(ctx)

    role_arn = _create_role(
        ctx,
        "sm-role",
        trust_services=["events.amazonaws.com", "states.amazonaws.com"],
        inline_statements=[
            {"Effect": "Allow", "Action": "states:StartExecution", "Resource": "*"},
            {"Effect": "Allow", "Action": "backup:StartBackupJob", "Resource": "*"},
            {"Effect": "Allow", "Action": "iam:PassRole", "Resource": backup_svc_role_arn},
        ],
    )

    sm_name = ctx.unique_name("sim2real-beh-sm-")
    definition = {
        "Comment": "invoke backup:StartBackupJob",
        "StartAt": "StartBackupJob",
        "States": {
            "StartBackupJob": {
                "Type": "Task",
                "Resource": "arn:aws:states:::aws-sdk:backup:startBackupJob",
                "Parameters": {
                    "BackupVaultName": vault_name,
                    "ResourceArn": table_arn,
                    "IamRoleArn": backup_svc_role_arn,
                },
                "End": True,
            }
        },
    }
    sm_arn = _create_state_machine(ctx, sfn, sm_name, role_arn, definition)

    rule_name = ctx.unique_name("sim2real-beh-rule-")
    pattern = {"source": ["sim2real.test"], "detail-type": ["trigger-backup"]}
    events.put_rule(
        Name=rule_name,
        EventPattern=json.dumps(pattern),
        State="ENABLED",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: _delete_rule(events, rule_name, ["sfn-target"]))
    events.put_targets(
        Rule=rule_name, Targets=[{"Id": "sfn-target", "Arn": sm_arn, "RoleArn": role_arn}]
    )

    entry = {"Source": "sim2real.test", "DetailType": "trigger-backup", "Detail": "{}"}
    execution = _fire_until_execution(events, sfn, sm_arn, entry)
    assert execution is not None, "expected EventBridge to invoke the Step Functions target"
    final = _wait_execution_terminal(sfn, execution["executionArn"], timeout_s=60.0)
    assert final["status"] == "SUCCEEDED", f"state machine execution did not succeed: {final}"

    assert _wait_for_backup_job(backup, table_arn, execution["startDate"].timestamp() - 2.0, timeout_s=60.0), (
        "expected a real AWS Backup job to be created for the target DynamoDB table"
    )


def _now_ts() -> float:
    return dt.datetime.now(dt.timezone.utc).timestamp() - 2.0


def _create_table(ctx) -> tuple[str, str]:
    ddb = ctx.client("dynamodb")
    name = ctx.unique_name("sim2real-beh-tbl-")
    resp = ddb.create_table(
        TableName=name,
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        BillingMode="PAY_PER_REQUEST",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=name))
    ddb.get_waiter("table_exists").wait(TableName=name, WaiterConfig={"Delay": 2, "MaxAttempts": 250})
    return name, resp["TableDescription"]["TableArn"]


def _create_vault(ctx) -> tuple[str, str]:
    backup = ctx.client("backup")
    name = ctx.unique_name("sim2real-beh-vault-")
    resp = backup.create_backup_vault(
        BackupVaultName=name, BackupVaultTags={"sim2real": CHECK}
    )
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
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]["Arn"]
    policy_arn = "arn:aws:iam::aws:policy/service-role/AWSBackupServiceRolePolicyForBackup"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
    ctx.on_cleanup(lambda: _delete_role(iam, role_name, [policy_arn]))
    return role_arn


def _create_role(ctx, kind: str, trust_services: list[str], inline_statements: list[dict]) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name(f"sim2real-beh-{kind}-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": svc}, "Action": "sts:AssumeRole"}
            for svc in trust_services
        ],
    }
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: _delete_role(iam, role_name, []))
    if inline_statements:
        policy_doc = {"Version": "2012-10-17", "Statement": inline_statements}
        iam.put_role_policy(
            RoleName=role_name, PolicyName="inline-perms", PolicyDocument=json.dumps(policy_doc)
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
        for pname in iam.list_role_policies(RoleName=role_name).get("PolicyNames", []):
            iam.delete_role_policy(RoleName=role_name, PolicyName=pname)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise
    try:
        iam.delete_role(RoleName=role_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _create_state_machine(ctx, sfn, name: str, role_arn: str, definition: dict) -> str:
    deadline = time.monotonic() + 60.0
    last_exc: Exception | None = None
    while time.monotonic() < deadline:
        try:
            resp = sfn.create_state_machine(
                name=name,
                definition=json.dumps(definition),
                roleArn=role_arn,
                type="STANDARD",
                tags=[{"key": "sim2real", "value": CHECK}],
            )
            sm_arn = resp["stateMachineArn"]
            ctx.on_cleanup(lambda: sfn.delete_state_machine(stateMachineArn=sm_arn))
            return sm_arn
        except ClientError as exc:
            last_exc = exc
            time.sleep(4.0)
    raise AssertionError(f"create_state_machine never succeeded (IAM propagation?): {last_exc}")


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


def _wait_for_new_execution(sfn, sm_arn: str, after_ts: float, timeout_s: float = 90.0):
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        resp = sfn.list_executions(stateMachineArn=sm_arn, maxResults=20)
        for execn in resp.get("executions", []):
            if execn["startDate"].timestamp() >= after_ts:
                return execn
        time.sleep(3.0)
    return None


def _fire_until_execution(events, sfn, sm_arn: str, entry: dict, attempts: int = 6, poll_s: float = 20.0, gap_s: float = 15.0):
    """EventBridge does not retry target invocations that fail with AccessDenied
    (IAM propagation lag right after role/policy creation is not retryable), so
    re-fire the triggering event ourselves until the role has propagated."""
    for _ in range(attempts):
        after_ts = _now_ts()
        events.put_events(Entries=[entry])
        execution = _wait_for_new_execution(sfn, sm_arn, after_ts, timeout_s=poll_s)
        if execution is not None:
            return execution
        time.sleep(gap_s)
    return None


def _wait_execution_terminal(sfn, exec_arn: str, timeout_s: float = 60.0) -> dict:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        resp = sfn.describe_execution(executionArn=exec_arn)
        if resp["status"] != "RUNNING":
            return resp
        time.sleep(3.0)
    raise AssertionError(f"execution {exec_arn} never reached a terminal state")


def _wait_for_backup_job(backup, resource_arn: str, after_ts: float, timeout_s: float = 60.0) -> bool:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        jobs = backup.list_backup_jobs(ByResourceArn=resource_arn).get("BackupJobs", [])
        for job in jobs:
            if job["CreationDate"].timestamp() >= after_ts:
                return True
        time.sleep(3.0)
    return False


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
