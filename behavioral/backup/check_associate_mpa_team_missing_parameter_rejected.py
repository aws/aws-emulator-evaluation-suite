"""associate-mpa-team-missing-parameter-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "associate-mpa-team-missing-parameter-rejected"
GROUP = "error-semantics"
SERVICES = ["backup"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """AssociateBackupVaultMpaApprovalTeam with an empty team ARN fails with
    InvalidParameterValueException on an existing vault and leaves no association; on a
    nonexistent vault it gets AccessDeniedException."""
    backup = ctx.client("backup")
    vault_name = ctx.unique_name("sim2real-mpa-")
    missing_vault_name = ctx.unique_name("sim2real-mpa-missing-")

    create_resp = backup.create_backup_vault(
        BackupVaultName=vault_name,
        BackupVaultTags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-mpa"},
    )
    ctx.on_cleanup(lambda: backup.delete_backup_vault(BackupVaultName=vault_name))

    # Positive control: an unrelated mutation on the same vault succeeds, so the rejections
    # below are specific to the call.
    vault_arn = create_resp["BackupVaultArn"]
    backup.tag_resource(ResourceArn=vault_arn, Tags={"sim2real-check": "true"})
    tag_value = backup.list_tags(ResourceArn=vault_arn)["Tags"].get("sim2real-check")
    assert tag_value == "true", f"actual_tag_value={tag_value}"

    code, message = _error(
        lambda: backup.associate_backup_vault_mpa_approval_team(
            BackupVaultName=vault_name, MpaApprovalTeamArn=""
        )
    )
    assert code == "InvalidParameterValueException", f"actual_code={code}"
    assert message == "Parameter MpaApprovalTeamArn is invalid.", f"actual_message={message!r}"

    described = backup.describe_backup_vault(BackupVaultName=vault_name)
    assert described.get("MpaApprovalTeamArn") is None, (
        f"unexpected MpaApprovalTeamArn set: {described.get('MpaApprovalTeamArn')}"
    )

    # Same call shape, but the target vault does not exist -- rejected for resource-based
    # authorization reasons (AccessDeniedException), a distinct, specific failure mode from the
    # parameter-value rejection above.
    other_code, other_message = _error(
        lambda: backup.associate_backup_vault_mpa_approval_team(
            BackupVaultName=missing_vault_name,
            MpaApprovalTeamArn=f"arn:aws:mpa:{ctx.region}:{ctx.account}:approval-team/does-not-exist",
        )
    )
    assert other_code == "AccessDeniedException", f"actual_code={other_code}"
    assert other_message == "Insufficient privileges to perform this action.", f"actual_message={other_message!r}"


def _error(fn):
    """Call fn(); return the ClientError's (code, message). An unexpected success raises,
    so accepting a request AWS refuses fails the check."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

