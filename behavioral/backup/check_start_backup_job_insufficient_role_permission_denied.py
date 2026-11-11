"""start-backup-job-insufficient-role-permission-denied."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "start-backup-job-insufficient-role-permission-denied"
GROUP = "overly-permissive"
SERVICES = ["backup"]


@tags("axis:rejection", "cap:c4", "cap:c7", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """StartBackupJob from an identity denied backup:StartBackupJob fails with AccessDeniedException
    and creates no job, while the same call from a permitted caller is accepted and its job
    advances past CREATED/PENDING."""
    table = _create_table(ctx)
    vault_name = _create_vault(ctx)
    service_role_arn = _create_backup_service_role(ctx)
    denied_creds = _create_denied_caller_user(ctx)

    denied_backup = _client_from_keys(ctx, denied_creds, "backup")
    code, message, job_id = _poll_start_job_denied(denied_backup, vault_name, table["arn"], service_role_arn)
    assert code == "AccessDeniedException", f"expected AccessDeniedException, got {code}"
    expected_message = f"User: {denied_creds['UserArn']} is not authorized to perform: backup:StartBackupJob on resource: arn:aws:backup:{ctx.region}:{ctx.account}:backup-vault:{vault_name} with an explicit deny in an identity-based policy"
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"
    assert job_id is None, f"denied caller unexpectedly started a job: {job_id}"

    # effect absent: no backup job was created for this resource by the denied caller
    admin_backup = ctx.client("backup")
    jobs = admin_backup.list_backup_jobs(ByResourceArn=table["arn"])["BackupJobs"]
    assert jobs == [], f"expected no backup jobs for {table['arn']}, found {jobs}"

    # positive control: the identical call from a fully-permissioned caller succeeds AND the
    # resulting job is genuinely picked up and processed, not just accepted and left inert
    resp = _start_backup_job_with_role_retry(ctx, vault_name, table["arn"], service_role_arn)
    ctrl_job_id = resp
    ctx.on_cleanup(lambda: _cleanup_recovery_point(ctx, vault_name, ctrl_job_id))
    state = _poll_backup_job_progressing(ctx, ctrl_job_id)
    assert state in ("RUNNING", "COMPLETED"), f"unexpected state {state}"


def _safe_call(fn):
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in (
            "NoSuchEntity",
            "ResourceNotFoundException",
            "TableNotFoundException",
        ):
            raise


def _start_backup_job_with_role_retry(ctx, vault_name, resource_arn, role_arn, timeout_s=120, interval_s=5):
    """A freshly-created IAM role is not always immediately usable by the AWS Backup service
    (IAM permission propagation lag); retry StartBackupJob on the transient
    InvalidParameterValueException/'insufficient permissions' response until it clears."""
    backup = ctx.client("backup")
    deadline = time.monotonic() + timeout_s
    last_err = None
    while time.monotonic() < deadline:
        try:
            return backup.start_backup_job(
                BackupVaultName=vault_name, ResourceArn=resource_arn, IamRoleArn=role_arn
            )["BackupJobId"]
        except ClientError as err:
            code = err.response["Error"]["Code"]
            msg = err.response["Error"].get("Message", "")
            if code == "InvalidParameterValueException" and "permission" in msg.lower():
                last_err = err
                time.sleep(interval_s)
                continue
            raise
    raise AssertionError(f"StartBackupJob role permissions never propagated within {timeout_s}s: {last_err}")


def _cleanup_recovery_point(ctx, vault_name, job_id):
    backup = ctx.client("backup")
    try:
        rp_arn = backup.describe_backup_job(BackupJobId=job_id).get("RecoveryPointArn")
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise
        return
    if rp_arn:
        _safe_call(lambda: backup.delete_recovery_point(BackupVaultName=vault_name, RecoveryPointArn=rp_arn))


def _create_table(ctx):
    ddb = ctx.client("dynamodb")
    name = ctx.unique_name("sim2real-backup-tbl-")
    ddb.create_table(
        TableName=name,
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
    )
    ctx.on_cleanup(lambda: _safe_call(lambda: ddb.delete_table(TableName=name)))
    ddb.get_waiter("table_exists").wait(TableName=name, WaiterConfig={"Delay": 2, "MaxAttempts": 250})
    arn = ddb.describe_table(TableName=name)["Table"]["TableArn"]
    return {"name": name, "arn": arn}


def _create_vault(ctx):
    backup = ctx.client("backup")
    name = ctx.unique_name("sim2real-backup-vault-")
    backup.create_backup_vault(
        BackupVaultName=name,
        BackupVaultTags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-backup"},
    )
    ctx.on_cleanup(lambda: _safe_call(lambda: backup.delete_backup_vault(BackupVaultName=name)))
    return name


def _create_backup_service_role(ctx):
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-backup-svcrole-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "backup.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    role_arn = iam.create_role(
        RoleName=name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
    )["Role"]["Arn"]
    policy_arn = "arn:aws:iam::aws:policy/service-role/AWSBackupServiceRolePolicyForBackup"
    iam.attach_role_policy(RoleName=name, PolicyArn=policy_arn)
    ctx.on_cleanup(lambda: _safe_call(lambda: iam.delete_role(RoleName=name)))
    ctx.on_cleanup(lambda: _safe_call(lambda: iam.detach_role_policy(RoleName=name, PolicyArn=policy_arn)))
    return role_arn


def _create_denied_caller_user(ctx):
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-backup-denied-")
    user_arn = iam.create_user(UserName=name, Tags=[{"Key": "sim2real:managed", "Value": "true"}])["User"]["Arn"]
    ctx.on_cleanup(lambda: _safe_call(lambda: iam.delete_user(UserName=name)))
    deny_policy = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Deny", "Action": "backup:StartBackupJob", "Resource": "*"}],
    }
    iam.put_user_policy(UserName=name, PolicyName="deny-start-backup-job", PolicyDocument=json.dumps(deny_policy))
    ctx.on_cleanup(
        lambda: _safe_call(lambda: iam.delete_user_policy(UserName=name, PolicyName="deny-start-backup-job"))
    )
    creds = iam.create_access_key(UserName=name)["AccessKey"]
    ctx.on_cleanup(
        lambda: _safe_call(lambda: iam.delete_access_key(UserName=name, AccessKeyId=creds["AccessKeyId"]))
    )
    return {**creds, "UserArn": user_arn}


def _client_from_keys(ctx, creds, service):
    return ctx.client(
        service,
        creds={"aws_access_key_id": creds["AccessKeyId"], "aws_secret_access_key": creds["SecretAccessKey"]},
    )


def _poll_start_job_denied(denied_backup, vault_name, resource_arn, role_arn, timeout_s=60, interval_s=3):
    """New IAM access keys can take a few seconds to propagate; retry transient
    InvalidClientTokenId/UnrecognizedClientException responses until the explicit-deny
    AccessDeniedException (the durable, expected outcome) is observed."""
    deadline = time.monotonic() + timeout_s
    last_code = last_message = None
    while time.monotonic() < deadline:
        try:
            resp = denied_backup.start_backup_job(
                BackupVaultName=vault_name, ResourceArn=resource_arn, IamRoleArn=role_arn
            )
            return None, None, resp.get("BackupJobId")
        except ClientError as err:
            last_code = err.response["Error"]["Code"]
            last_message = err.response["Error"].get("Message", "")
            if last_code not in ("InvalidClientTokenId", "UnrecognizedClientException"):
                return last_code, last_message, None
        time.sleep(interval_s)
    return last_code, last_message, None


def _poll_backup_job_progressing(ctx, job_id, timeout_s=90, interval_s=5):
    """Proves the accepted job is being processed, not merely accepted and left inert, by
    requiring it to advance out of CREATED/PENDING within a bounded window: an on-demand DynamoDB
    backup job reaches RUNNING well within it, while COMPLETED can take several minutes more."""
    backup = ctx.client("backup")
    deadline = time.monotonic() + timeout_s
    last_state = None
    while time.monotonic() < deadline:
        resp = backup.describe_backup_job(BackupJobId=job_id)
        last_state = resp["State"]
        if last_state in ("FAILED", "ABORTED", "EXPIRED"):
            raise AssertionError(f"backup job {job_id} entered {last_state}: {resp.get('StatusMessage')}")
        if last_state in ("RUNNING", "COMPLETED"):
            return last_state
        time.sleep(interval_s)
    raise AssertionError(
        f"backup job {job_id} did not advance past CREATED/PENDING within {timeout_s}s (last {last_state})"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
