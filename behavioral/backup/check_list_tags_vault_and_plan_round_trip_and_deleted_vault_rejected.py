"""list-tags-vault-and-plan-round-trip-and-deleted-vault-rejected."""

from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "list-tags-vault-and-plan-round-trip-and-deleted-vault-rejected"
GROUP = "tagging"
SERVICES = ["backup"]


@tags(
    "axis:rejection",
    "cap:c1",
    "concern:negative-classes",
    "concern:representation",
    "plane:control",
)
def run(ctx) -> None:
    """ListTags on a vault ARN and a plan ARN returns exactly the create-time plus TagResource tags,
    UntagResource removes only the named key, and ListTags on a deleted vault's ARN is refused.

    Reference: https://docs.aws.amazon.com/aws-backup/latest/devguide/API_ListTags.html
    """
    bak = ctx.client("backup")

    vault = ctx.unique_name("sim2real-behav-bkvt-")
    vault_arn = bak.create_backup_vault(BackupVaultName=vault, BackupVaultTags={"team": "storage"})[
        "BackupVaultArn"
    ]
    ctx.on_cleanup(
        _teardown(
            lambda: bak.delete_backup_vault(BackupVaultName=vault), "ResourceNotFoundException"
        )
    )

    plan = bak.create_backup_plan(
        BackupPlan={
            "BackupPlanName": ctx.unique_name("sim2real-behav-bkpl-"),
            "Rules": [
                {
                    "RuleName": "daily",
                    "TargetBackupVaultName": vault,
                    "ScheduleExpression": "cron(0 5 ? * * *)",
                }
            ],
        },
        BackupPlanTags={"tier": "gold"},
    )
    plan_id, plan_arn = plan["BackupPlanId"], plan["BackupPlanArn"]
    ctx.on_cleanup(
        _teardown(lambda: bak.delete_backup_plan(BackupPlanId=plan_id), "ResourceNotFoundException")
    )

    for arn, created, added, removed in (
        (vault_arn, {"team": "storage"}, {"env": "dev", "owner": "data"}, "team"),
        (plan_arn, {"tier": "gold"}, {"env": "dev"}, "tier"),
    ):
        got = _poll_tags(bak, arn, created)
        assert got == created, (
            f"ListTags({arn!r}) after create returned {got!r}, expected {created!r}"
        )

        bak.tag_resource(ResourceArn=arn, Tags=added)
        merged = {**created, **added}
        got = _poll_tags(bak, arn, merged)
        assert got == merged, (
            f"ListTags({arn!r}) after TagResource returned {got!r}, expected {merged!r}"
        )

        bak.untag_resource(ResourceArn=arn, TagKeyList=[removed])
        left = {k: v for k, v in merged.items() if k != removed}
        got = _poll_tags(bak, arn, left)
        assert got == left, (
            f"ListTags({arn!r}) after UntagResource returned {got!r}, expected {left!r}"
        )

    # A second vault is deleted: its ARN stops resolving while the first vault's still does.
    doomed = ctx.unique_name("sim2real-behav-bkvt-")
    doomed_arn = bak.create_backup_vault(
        BackupVaultName=doomed, BackupVaultTags={"team": "storage"}
    )["BackupVaultArn"]
    gone = []
    ctx.on_cleanup(
        lambda: (
            gone
            or _teardown(
                lambda: bak.delete_backup_vault(BackupVaultName=doomed), "ResourceNotFoundException"
            )()
        )
    )
    got = _poll_tags(bak, doomed_arn, {"team": "storage"})
    assert got == {"team": "storage"}, f"ListTags on the second vault returned {got!r}"

    bak.delete_backup_vault(BackupVaultName=doomed)
    gone.append(True)

    err = _error(lambda: bak.list_tags(ResourceArn=doomed_arn))
    want = ("AccessDeniedException", "Insufficient privileges to perform this action.")
    assert err == want, f"ListTags on a deleted vault's ARN returned {err!r}, expected {want!r}"

    survivor = bak.list_tags(ResourceArn=vault_arn)["Tags"]
    assert survivor == {"env": "dev", "owner": "data"}, (
        f"the remaining vault's tags read back as {survivor!r} after the other vault's delete"
    )


# ===== helpers =====


def _poll_tags(bak, arn: str, want: dict, timeout_s: float = 30.0) -> dict:
    """ListTags until it equals ``want`` or the bound passes; returns the last read."""
    deadline = time.monotonic() + timeout_s
    while True:
        got = bak.list_tags(ResourceArn=arn)["Tags"]
        if got == want or time.monotonic() >= deadline:
            return got
        time.sleep(2)


def _error(fn) -> tuple:
    """(code, message) of the AWS error ``fn`` raises. Raises if the call unexpectedly succeeds."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"call unexpectedly succeeded and returned {result!r}")


def _teardown(undo, *not_found: str):
    """A cleanup running ``undo()`` where a failed delete raises; only ``not_found`` means gone."""

    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
