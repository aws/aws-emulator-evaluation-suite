"""deploy-backup-vault-cfn-behaves."""
from __future__ import annotations

import json

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-backup-vault-cfn-behaves"
GROUP = "state-machine"
SERVICES = ["backup"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:deploy", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A CloudFormation-deployed backup vault accepts and returns an access policy and is listed;
    deleting the stack removes it from the list and DescribeBackupVault is then rejected."""
    cfn = ctx.client("cloudformation")
    backup = ctx.client("backup")
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    stack_name = ctx.unique_name("sim2real-backup-cfn-")
    vault_name = ctx.unique_name("sim2real-backup-cfnvault-")

    template = json.dumps(
        {
            "AWSTemplateFormatVersion": "2010-09-09",
            "Resources": {
                "Vault": {
                    "Type": "AWS::Backup::BackupVault",
                    "Properties": {"BackupVaultName": vault_name},
                }
            },
            "Outputs": {
                "VaultName": {"Value": {"Ref": "Vault"}},
                "VaultArn": {"Value": {"Fn::GetAtt": ["Vault", "BackupVaultArn"]}},
            },
        }
    )

    cfn.create_stack(
        StackName=stack_name,
        TemplateBody=template,
        Tags=[{"Key": "sim2real", "Value": "true"}],
    )
    ctx.on_cleanup(lambda: _safe_call(lambda: cfn.delete_stack(StackName=stack_name)))
    cfn.get_waiter("stack_create_complete").wait(
        StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 150}
    )

    outputs = {
        o["OutputKey"]: o["OutputValue"]
        for o in cfn.describe_stacks(StackName=stack_name)["Stacks"][0].get("Outputs", [])
    }
    deployed_vault_name = outputs["VaultName"]
    deployed_vault_arn = outputs["VaultArn"]
    assert deployed_vault_name == vault_name, (
        f"stack output VaultName {deployed_vault_name!r} != requested {vault_name!r}"
    )

    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "AllowSameAccountDescribeRecoveryPoint",
                "Effect": "Allow",
                "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"},
                "Action": "backup:DescribeRecoveryPoint",
                "Resource": deployed_vault_arn,
            }
        ],
    }
    backup.put_backup_vault_access_policy(BackupVaultName=deployed_vault_name, Policy=json.dumps(policy))
    fetched = json.loads(backup.get_backup_vault_access_policy(BackupVaultName=deployed_vault_name)["Policy"])
    assert fetched["Statement"][0]["Sid"] == "AllowSameAccountDescribeRecoveryPoint", (
        f"unexpected Sid on read-back policy: {fetched['Statement'][0]}"
    )
    assert fetched["Statement"][0]["Resource"] == deployed_vault_arn, (
        f"policy Resource {fetched['Statement'][0]['Resource']!r} != vault arn {deployed_vault_arn!r}"
    )

    names = {v["BackupVaultName"] for v in _list_all_vaults(backup)}
    assert deployed_vault_name in names, f"{deployed_vault_name} not visible in ListBackupVaults"

    cfn.delete_stack(StackName=stack_name)
    cfn.get_waiter("stack_delete_complete").wait(
        StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 150}
    )

    code, message = _poll_until(
        lambda: _describe_error(backup, deployed_vault_name),
        lambda err: err[0] == "AccessDeniedException",
        timeout_s=30,
        interval_s=2,
        description="post-stack-deletion describe rejected with AccessDenied",
    )
    assert code == "AccessDeniedException", (
        f"expected AccessDeniedException for deployed_vault_name after stack deletion, got {code!r}"
    )
    assert message == "Insufficient privileges to perform this action.", f"actual_message={message!r}"
    names_after_delete = {v["BackupVaultName"] for v in _list_all_vaults(backup)}
    assert deployed_vault_name not in names_after_delete, (
        f"{deployed_vault_name} still visible in ListBackupVaults after stack deletion"
    )


def _safe_call(fn) -> None:
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "StackNotFoundException":
            raise


def _describe_error(backup, vault_name):
    """Poll probe: DescribeBackupVault's refusal as (code, message), or ("<exists>", None) while
    the vault is still describable, so a still-present vault never reads as a refusal."""
    try:
        backup.describe_backup_vault(BackupVaultName=vault_name)
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    return "<exists>", None


def _poll_until(probe, pred, *, timeout_s=60.0, interval_s=2.0, description="condition"):
    import time

    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if pred(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s; last result: {last!r}")


def _list_all_vaults(backup):
    vaults = []
    token = None
    while True:
        kwargs = {"NextToken": token} if token else {}
        resp = backup.list_backup_vaults(**kwargs)
        vaults.extend(resp["BackupVaultList"])
        token = resp.get("NextToken")
        if not token:
            return vaults


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
