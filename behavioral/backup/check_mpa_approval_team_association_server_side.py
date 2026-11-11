"""mpa-approval-team-association-server-side."""
from __future__ import annotations

import time
import uuid

from behavioral_harness import tags

CHECK = "mpa-approval-team-association-server-side"
GROUP = "server-side"
SERVICES = ["backup"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Associating a well-formed but nonexistent MPA approval-team ARN with a logically air-gapped
    vault is rejected with InvalidParameterValueException and leaves no association;
    disassociating a vault that never had a team succeeds as a no-op."""
    backup = ctx.client("backup")
    sts = ctx.client("sts")

    vault_name = ctx.unique_name("sim2real-mpa-vault-")
    backup.create_logically_air_gapped_backup_vault(
        BackupVaultName=vault_name,
        MinRetentionDays=7,
        MaxRetentionDays=30,
        BackupVaultTags={"sim2real-check": CHECK},
    )
    ctx.on_cleanup(lambda: backup.delete_backup_vault(BackupVaultName=vault_name))

    created = _poll_until(
        lambda: backup.describe_backup_vault(BackupVaultName=vault_name),
        lambda r: r["VaultState"] in ("AVAILABLE", "FAILED"),
        timeout_s=600,
        interval_s=10,
    )
    assert created["VaultState"] == "AVAILABLE", (
        f"vault did not become AVAILABLE, got {created['VaultState']!r}"
    )

    # Positive control: an unrelated mutation on this same vault still succeeds,
    # so a rejected associate call below cannot be explained by an unhealthy
    # account/vault or a blanket-deny on the vault's ARN.
    vault_arn = created["BackupVaultArn"]
    backup.tag_resource(ResourceArn=vault_arn, Tags={"sim2real-control": "true"})
    control_tags = backup.list_tags(ResourceArn=vault_arn)["Tags"]
    assert control_tags.get("sim2real-control") == "true", (
        "positive control failed: tagging the vault itself did not take effect"
    )

    account_id = sts.get_caller_identity()["Account"]
    fake_team_arn = f"arn:aws:mpa:{ctx.region}:{account_id}:approval-team/{uuid.uuid4()}"

    code, message = _error(
        lambda: backup.associate_backup_vault_mpa_approval_team(
            BackupVaultName=vault_name, MpaApprovalTeamArn=fake_team_arn
        )
    )
    assert code == "InvalidParameterValueException", f"unexpected associate error code: {code}"
    expected_message = "Parameter MpaApprovalTeamArn is invalid."
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    described = backup.describe_backup_vault(BackupVaultName=vault_name)
    assert described.get("MpaApprovalTeamArn") is None, (
        "vault shows an MPA approval team association despite the associate "
        "call failing"
    )

    # Disassociating a vault that never had an MPA approval team attached
    # is a no-op: it succeeds idempotently rather than raising an error.
    backup.disassociate_backup_vault_mpa_approval_team(BackupVaultName=vault_name)

    # Terminal read: an independent describe (not the disassociate call's own
    # response) confirms the no-op left the vault's MPA state untouched.
    after_disassociate = backup.describe_backup_vault(BackupVaultName=vault_name)
    assert after_disassociate.get("MpaApprovalTeamArn") is None, (
        "vault shows an MPA approval team association after a no-op disassociate"
    )


def _error(fn, *, timeout_s: float = 0.0, interval_s: float = 3.0):
    """Call fn() until it is refused; return the refusal's (code, message). A call that still
    SUCCEEDS once timeout_s has passed raises, because a target accepting a call real AWS refuses
    must not read as a code mismatch."""
    import time

    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    while True:
        try:
            result = fn()
        except ClientError as err:
            return err.response["Error"]["Code"], err.response["Error"].get("Message", "")
        if time.monotonic() >= deadline:
            raise AssertionError(f"expected the call to be refused, but it SUCCEEDED and returned {result!r}")
        time.sleep(interval_s)


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)

