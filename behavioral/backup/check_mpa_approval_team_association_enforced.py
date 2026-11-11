"""mpa-approval-team-association-enforced."""
from __future__ import annotations

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "mpa-approval-team-association-enforced"
GROUP = "server-side"
SERVICES = ["backup"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """On a plain vault, which does not support MPA, disassociating with no team set and associating
    a nonexistent team ARN are both rejected with InvalidParameterValueException and leave the
    vault's MPA state unchanged, while an unrelated vault mutation still succeeds."""
    backup = ctx.client("backup")
    vault_name = _create_vault(ctx)

    code, message = _error(lambda: backup.disassociate_backup_vault_mpa_approval_team(BackupVaultName=vault_name))
    assert code == "InvalidParameterValueException", (
        f"expected disassociating a non-associated MPA team on a vault type that does not "
        f"support MPA to be rejected with InvalidParameterValueException, got {code}"
    )
    expected_message = "Operation not supported for the provided vault type"
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    bogus_team_arn = f"arn:aws:mpa:{ctx.region}:111122223333:approval-team/sim2real-does-not-exist"
    code2, message2 = _error(
        lambda: backup.associate_backup_vault_mpa_approval_team(
            BackupVaultName=vault_name, MpaApprovalTeamArn=bogus_team_arn
        )
    )
    assert code2 == "InvalidParameterValueException", (
        f"expected a non-existent MPA team ARN to be rejected with InvalidParameterValueException, got {code2}"
    )
    expected_message2 = "Parameter MpaApprovalTeamArn is invalid."
    assert message2 == expected_message2, f"expected message {expected_message2!r}, got {message2!r}"

    # effect absent: vault still has no MPA approval team associated
    desc = backup.describe_backup_vault(BackupVaultName=vault_name)
    assert not desc.get("MpaApprovalTeamArn"), f"unexpected MpaApprovalTeamArn set: {desc.get('MpaApprovalTeamArn')}"

    # positive control: an unrelated vault mutation still succeeds normally
    vault_arn = desc["BackupVaultArn"]
    backup.tag_resource(ResourceArn=vault_arn, Tags={"sim2real-check": "true"})
    tags_resp = backup.list_tags(ResourceArn=vault_arn)["Tags"]
    assert tags_resp.get("sim2real-check") == "true"


def _error(fn):
    """Call fn(); return its botocore error (code, message). An unexpected SUCCESS raises, because an
    over-permissive target accepting input real AWS refuses must not read as an
    error-code mismatch."""
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message", "")
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


def _create_vault(ctx):
    backup = ctx.client("backup")
    name = ctx.unique_name("sim2real-backup-vault-")
    backup.create_backup_vault(BackupVaultName=name)
    ctx.on_cleanup(lambda: backup.delete_backup_vault(BackupVaultName=name))
    return name


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
