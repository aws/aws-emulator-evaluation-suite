"""eventbridge-rule-target-missing-startbackupjob-permission-denied."""
from __future__ import annotations

import json
import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "eventbridge-rule-target-missing-startbackupjob-permission-denied"
GROUP = "overly-permissive"
SERVICES = ["backup", "events"]


@tags("axis:negative-delivery", "cap:c3", "cap:c7", "concern:data-plane", "concern:e2e", "concern:eventing", "concern:negative-classes", "dp:api", "plane:data", "resource:account-singleton:backup-region-settings")
def run(ctx) -> None:
    """The role driving an EventBridge-triggered Step Functions execution needs its own
    backup:StartBackupJob permission: without it, the execution fires but reaches FAILED and no
    backup job is created, while an identical chain with the permission succeeds."""
    events_client = ctx.client("events")
    sfn = ctx.client("stepfunctions")
    backup = ctx.client("backup")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]

    _ensure_dynamodb_opted_in(ctx)
    backup_role_arn, _ = _create_backup_service_role(ctx)
    table_name, table_arn = _create_table(ctx)
    vault_name, vault_arn = _create_vault(ctx)

    # A role trusted by Step Functions (and, for the pinned-error probe below, assumable by our
    # own test principal) that deliberately has NO backup permissions attached at all.
    limited_role_arn, limited_role_name = _create_role(
        ctx, [{"Service": "states.amazonaws.com"}, {"AWS": account_id}]
    )

    assumed = _retry(
        lambda: sts.assume_role(RoleArn=limited_role_arn, RoleSessionName="sim2real-negcheck")["Credentials"],
        retry_codes={"AccessDenied"},
    )
    limited_backup = ctx.client("backup", creds={
        "aws_access_key_id": assumed["AccessKeyId"],
        "aws_secret_access_key": assumed["SecretAccessKey"],
        "aws_session_token": assumed["SessionToken"],
    })
    code, message = _wait_for_denied(
        lambda: limited_backup.start_backup_job(
            BackupVaultName=vault_name, ResourceArn=table_arn, IamRoleArn=backup_role_arn
        )
    )
    assert code == "AccessDeniedException", f"expected AccessDeniedException for the unpermissioned role, got {code}"
    expected_message = (
        f"User: arn:aws:sts::{account_id}:assumed-role/{limited_role_name}/sim2real-negcheck is not "
        f"authorized to perform: backup:StartBackupJob on resource: {vault_arn} because no "
        f"identity-based policy allows the backup:StartBackupJob action"
    )
    assert message == expected_message, f"AccessDeniedException message {message!r}, expected {expected_message!r}"

    sm_arn = _create_state_machine(ctx, limited_role_arn, _sfn_def_start_backup_job())
    invoke_role_arn, _ = _create_events_invoke_role(ctx, sm_arn)

    rule_name = ctx.unique_name("sim2real-rule-")
    pattern = {"source": [f"sim2real.test.{rule_name}"], "detail-type": ["TriggerBackup"]}
    events_client.put_rule(Name=rule_name, EventPattern=json.dumps(pattern), State="ENABLED")
    ctx.on_cleanup(lambda: _safe(lambda: events_client.delete_rule(Name=rule_name), "ResourceNotFoundException"))
    target_input = json.dumps({"vaultName": vault_name, "resourceArn": table_arn, "iamRoleArn": backup_role_arn})
    _retry(
        lambda: events_client.put_targets(
            Rule=rule_name, Targets=[{"Id": "1", "Arn": sm_arn, "RoleArn": invoke_role_arn, "Input": target_input}]
        ),
        retry_codes={"ValidationException"},
    )
    ctx.on_cleanup(lambda: _safe(lambda: events_client.remove_targets(Rule=rule_name, Ids=["1"]), "ResourceNotFoundException"))
    entry = {"Source": pattern["source"][0], "DetailType": "TriggerBackup", "Detail": json.dumps({})}
    invoked = _fire_until_execution(events_client, sfn, sm_arn, entry)
    assert invoked, "expected the rule to invoke the state machine at least once (invoke role never propagated?)"

    executions = _poll_until(
        lambda: sfn.list_executions(stateMachineArn=sm_arn, statusFilter="FAILED").get("executions", []),
        lambda execs: len(execs) >= 1,
        timeout_s=90.0,
        interval_s=3.0,
    )
    assert executions, "expected the execution to reach FAILED because its role lacks backup:StartBackupJob"

    deadline = time.monotonic() + 20.0
    while time.monotonic() < deadline:
        jobs = backup.list_backup_jobs(ByResourceArn=table_arn).get("BackupJobs", [])
        assert jobs == [], f"no backup job should have been created without permission, found {jobs}"
        time.sleep(4.0)

    # -- positive control: an identical chain, but the role has the permission it needs.
    good_sfn_role_arn, _ = _create_sfn_exec_role(ctx, backup_role_arn, ["backup:StartBackupJob"])
    good_sm_arn = _create_state_machine(ctx, good_sfn_role_arn, _sfn_def_start_backup_job())
    good_invoke_role_arn, _ = _create_events_invoke_role(ctx, good_sm_arn)

    good_rule_name = ctx.unique_name("sim2real-rule-")
    good_pattern = {"source": [f"sim2real.test.{good_rule_name}"], "detail-type": ["TriggerBackup"]}
    events_client.put_rule(Name=good_rule_name, EventPattern=json.dumps(good_pattern), State="ENABLED")
    ctx.on_cleanup(lambda: _safe(lambda: events_client.delete_rule(Name=good_rule_name), "ResourceNotFoundException"))
    _retry(
        lambda: events_client.put_targets(
            Rule=good_rule_name,
            Targets=[{"Id": "1", "Arn": good_sm_arn, "RoleArn": good_invoke_role_arn, "Input": target_input}],
        ),
        retry_codes={"ValidationException"},
    )
    ctx.on_cleanup(lambda: _safe(lambda: events_client.remove_targets(Rule=good_rule_name, Ids=["1"]), "ResourceNotFoundException"))
    good_entry = {"Source": good_pattern["source"][0], "DetailType": "TriggerBackup", "Detail": json.dumps({})}
    good_invoked = _fire_until_execution(events_client, sfn, good_sm_arn, good_entry)
    assert good_invoked, "positive control: expected the rule to invoke the state machine at least once"

    good_executions = _poll_until(
        lambda: sfn.list_executions(stateMachineArn=good_sm_arn, statusFilter="SUCCEEDED").get("executions", []),
        lambda execs: len(execs) >= 1,
        timeout_s=90.0,
        interval_s=3.0,
    )
    assert good_executions, "positive control with correct permission should have succeeded"
    good_jobs = _poll_until(
        lambda: backup.list_backup_jobs(ByResourceArn=table_arn).get("BackupJobs", []),
        lambda js: len(js) >= 1,
        timeout_s=30.0,
        interval_s=3.0,
    )
    assert good_jobs and good_jobs[0]["State"] not in ("FAILED", "ABORTED", "EXPIRED"), (
        f"positive control expected a real, non-failed backup job, found {good_jobs}"
    )


# ===== helpers =====

def _safe(fn, *missing: str) -> None:
    """Run a teardown call: return on the given not-found codes, retry ResourceInUseException
    every 2 s for up to 60 s while a dependency is released, raise everything else."""
    deadline = time.monotonic() + 60
    while True:
        try:
            fn()
            return
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code in missing:
                return
            if code != "ResourceInUseException" or time.monotonic() >= deadline:
                raise
        time.sleep(2)


def _error(fn):
    """The (code, message) of the ClientError ``fn`` raises; a SUCCESS raises."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message", "")
    raise AssertionError(f"expected the call to be denied, but it SUCCEEDED and returned {result!r}")


def _wait_for_denied(fn, *, timeout_s: float = 45.0, interval_s: float = 3.0):
    """A just-assumed role's session credentials occasionally answer UnrecognizedClientException
    on the FIRST call to a regional service while STS propagation catches up -- transient, and
    distinct from AccessDeniedException, which is the terminal answer this probe is asserting."""
    deadline = time.monotonic() + timeout_s
    err = None
    while time.monotonic() < deadline:
        err = _error(fn)
        if err[0] != "UnrecognizedClientException":
            return err
        time.sleep(interval_s)
    return err


def _retry(fn, *, timeout_s: float = 45.0, interval_s: float = 3.0, retry_codes=None):
    deadline = time.monotonic() + timeout_s
    last_exc = None
    while time.monotonic() < deadline:
        try:
            return fn()
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if retry_codes is not None and code not in retry_codes:
                raise
            last_exc = e
            time.sleep(interval_s)
    raise last_exc


def _poll_until(probe, predicate, *, timeout_s: float = 60.0, interval_s: float = 3.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    return last


def _fire_until_execution(events_client, sfn, sm_arn: str, entry: dict, attempts: int = 6, poll_s: float = 20.0, gap_s: float = 15.0):
    """EventBridge does not retry a target invocation denied by IAM (the invoke role's trust
    policy has not propagated yet right after role/rule creation), so re-fire the triggering
    event ourselves until the role has propagated and an execution actually starts."""
    for _ in range(attempts):
        events_client.put_events(Entries=[entry])
        execs = _poll_until(
            lambda: sfn.list_executions(stateMachineArn=sm_arn).get("executions", []),
            lambda es: len(es) >= 1,
            timeout_s=poll_s,
            interval_s=3.0,
        )
        if execs:
            return True
        time.sleep(gap_s)
    return False


def _ensure_dynamodb_opted_in(ctx) -> None:
    backup = ctx.client("backup")
    try:
        settings = backup.describe_region_settings()
        prefs = dict(settings.get("ResourceTypeOptInPreference", {}))
        if not prefs.get("DynamoDB", False):
            original = dict(prefs)
            prefs["DynamoDB"] = True
            backup.update_region_settings(ResourceTypeOptInPreference=prefs)
            # the opt-in preferences are region-wide: put back exactly the map read above. Unlike
            # the resource cleanups this is not swallowed: a failed restore leaves the region
            # changed, so it must fail the teardown.
            ctx.on_cleanup(lambda: backup.update_region_settings(ResourceTypeOptInPreference=original))
    except ClientError:
        pass


def _delete_role_fully(iam, name: str) -> None:
    try:
        for p in iam.list_attached_role_policies(RoleName=name)["AttachedPolicies"]:
            _safe(lambda p=p: iam.detach_role_policy(RoleName=name, PolicyArn=p["PolicyArn"]), "NoSuchEntity")
        for pname in iam.list_role_policies(RoleName=name)["PolicyNames"]:
            _safe(lambda pname=pname: iam.delete_role_policy(RoleName=name, PolicyName=pname), "NoSuchEntity")
        iam.delete_role(RoleName=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _create_role(ctx, principals: list[dict[str, Any]], inline_policies=None, managed_policy_arns=None):
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": p, "Action": "sts:AssumeRole"} for p in principals],
    }
    role = iam.create_role(RoleName=name, AssumeRolePolicyDocument=json.dumps(trust))["Role"]
    ctx.on_cleanup(lambda: _delete_role_fully(iam, name))
    for arn in managed_policy_arns or []:
        iam.attach_role_policy(RoleName=name, PolicyArn=arn)
    for pname, doc in (inline_policies or {}).items():
        iam.put_role_policy(RoleName=name, PolicyName=pname, PolicyDocument=json.dumps(doc))
    return role["Arn"], name


def _create_backup_service_role(ctx):
    return _create_role(
        ctx,
        [{"Service": "backup.amazonaws.com"}],
        managed_policy_arns=["arn:aws:iam::aws:policy/service-role/AWSBackupServiceRolePolicyForBackup"],
    )


def _create_table(ctx):
    ddb = ctx.client("dynamodb")
    name = ctx.unique_name("sim2real-backup-tbl-")
    ddb.create_table(
        TableName=name,
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        BillingMode="PAY_PER_REQUEST",
    )
    ctx.on_cleanup(lambda: _safe(lambda: ddb.delete_table(TableName=name), "ResourceNotFoundException"))
    ddb.get_waiter("table_exists").wait(TableName=name, WaiterConfig={"Delay": 2, "MaxAttempts": 250})
    arn = ddb.describe_table(TableName=name)["Table"]["TableArn"]
    return name, arn


def _create_vault(ctx):
    backup = ctx.client("backup")
    name = ctx.unique_name("sim2real-vault-")
    resp = backup.create_backup_vault(BackupVaultName=name)

    def _busy(exc):
        msg = exc.response["Error"].get("Message", "")
        return exc.response["Error"]["Code"] == "InvalidRequestException" and (
            "active Backup Jobs" in msg or "already started the deletion" in msg or "recovery points" in msg
        )

    def _cleanup():
        # A running backup job keeps the vault refused, then leaves a recovery point to remove.
        deadline = time.monotonic() + 300.0
        while True:
            try:
                points = backup.list_recovery_points_by_backup_vault(BackupVaultName=name).get("RecoveryPoints", [])
            except ClientError as exc:
                if exc.response["Error"]["Code"] == "ResourceNotFoundException":
                    return
                raise
            for p in points:
                try:
                    backup.delete_recovery_point(BackupVaultName=name, RecoveryPointArn=p["RecoveryPointArn"])
                except ClientError as exc:
                    if exc.response["Error"]["Code"] != "ResourceNotFoundException" and not _busy(exc):
                        raise
            if not points:
                try:
                    backup.delete_backup_vault(BackupVaultName=name)
                    return
                except ClientError as exc:
                    if exc.response["Error"]["Code"] == "ResourceNotFoundException":
                        return
                    if not _busy(exc) or time.monotonic() >= deadline:
                        raise
            elif time.monotonic() >= deadline:
                raise AssertionError(f"vault {name} still holds recovery points after 300 s")
            time.sleep(2)

    ctx.on_cleanup(_cleanup)
    return name, resp["BackupVaultArn"]


def _sfn_def_start_backup_job() -> str:
    return json.dumps(
        {
            "Comment": "Start an on-demand AWS Backup job",
            "StartAt": "StartBackupJob",
            "States": {
                "StartBackupJob": {
                    "Type": "Task",
                    "Resource": "arn:aws:states:::aws-sdk:backup:startBackupJob",
                    "Parameters": {
                        "BackupVaultName.$": "$.vaultName",
                        "ResourceArn.$": "$.resourceArn",
                        "IamRoleArn.$": "$.iamRoleArn",
                    },
                    "End": True,
                }
            },
        }
    )


def _create_state_machine(ctx, role_arn: str, definition: str) -> str:
    sfn = ctx.client("stepfunctions")
    name = ctx.unique_name("sim2real-sm-")
    arn = _retry(
        lambda: sfn.create_state_machine(name=name, definition=definition, roleArn=role_arn, type="STANDARD")[
            "stateMachineArn"
        ],
        retry_codes={"AccessDeniedException"},
    )
    ctx.on_cleanup(lambda: _safe(lambda: sfn.delete_state_machine(stateMachineArn=arn), "StateMachineDoesNotExist"))
    return arn


def _create_sfn_exec_role(ctx, backup_role_arn: str, backup_actions: list[str]):
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Action": backup_actions, "Resource": "*"},
            {"Effect": "Allow", "Action": "iam:PassRole", "Resource": backup_role_arn},
        ],
    }
    return _create_role(ctx, [{"Service": "states.amazonaws.com"}], inline_policies={"backup-invoke": policy})


def _create_events_invoke_role(ctx, sm_arn: str):
    policy = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Action": "states:StartExecution", "Resource": sm_arn}],
    }
    return _create_role(ctx, [{"Service": "events.amazonaws.com"}], inline_policies={"invoke-sfn": policy})


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
