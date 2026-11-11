"""backup-vault-notifications-lifecycle."""
from __future__ import annotations

import json

from behavioral_harness import tags

CHECK = "backup-vault-notifications-lifecycle"
GROUP = "state-machine"
SERVICES = ["backup"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DeleteBackupVaultNotifications removes the stored notifications so Get returns
    ResourceNotFoundException; a second Delete succeeds, and a fresh Put is retrievable again."""
    backup = ctx.client("backup")
    sns = ctx.client("sns")
    vault_name = ctx.unique_name("sim2real-vaultnotif-")
    topic_name = ctx.unique_name("sim2real-vaultnotif-topic-")

    backup.create_backup_vault(BackupVaultName=vault_name)
    ctx.on_cleanup(lambda: backup.delete_backup_vault(BackupVaultName=vault_name))

    topic_arn = sns.create_topic(Name=topic_name)["TopicArn"]
    ctx.on_cleanup(lambda: sns.delete_topic(TopicArn=topic_arn))

    topic_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "AllowBackupPublish",
                "Effect": "Allow",
                "Principal": {"Service": "backup.amazonaws.com"},
                "Action": "SNS:Publish",
                "Resource": topic_arn,
            }
        ],
    }
    sns.set_topic_attributes(TopicArn=topic_arn, AttributeName="Policy", AttributeValue=json.dumps(topic_policy))

    events = ["BACKUP_JOB_STARTED", "BACKUP_JOB_COMPLETED"]
    backup.put_backup_vault_notifications(
        BackupVaultName=vault_name, SNSTopicArn=topic_arn, BackupVaultEvents=events
    )

    got = backup.get_backup_vault_notifications(BackupVaultName=vault_name)
    assert got["SNSTopicArn"] == topic_arn, f"expected topic {topic_arn!r}, got {got['SNSTopicArn']!r}"
    assert sorted(got["BackupVaultEvents"]) == sorted(events), (
        f"expected events {sorted(events)!r}, got {sorted(got['BackupVaultEvents'])!r}"
    )

    backup.delete_backup_vault_notifications(BackupVaultName=vault_name)

    code, message = _error(lambda: backup.get_backup_vault_notifications(BackupVaultName=vault_name))
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException after delete, got {code!r}"
    assert message == "Failed reading notifications from database for Backup vault", f"actual_message={message!r}"

    # A second delete on the already-empty config is a no-op success; a ClientError fails the check.
    second_delete = backup.delete_backup_vault_notifications(BackupVaultName=vault_name)
    second_delete_status = second_delete["ResponseMetadata"]["HTTPStatusCode"]
    assert second_delete_status == 200, (
        f"expected a second delete on an already-deleted notification config to be a no-op success, "
        f"got HTTP {second_delete_status}"
    )
    still_gone_code, still_gone_message = _error(
        lambda: backup.get_backup_vault_notifications(BackupVaultName=vault_name)
    )
    assert still_gone_code == "ResourceNotFoundException", (
        f"a no-op second delete must not resurrect the notification config, got {still_gone_code!r}"
    )
    assert still_gone_message == "Failed reading notifications from database for Backup vault", f"actual_message={still_gone_message!r}"

    backup.put_backup_vault_notifications(
        BackupVaultName=vault_name, SNSTopicArn=topic_arn, BackupVaultEvents=events
    )
    reput = backup.get_backup_vault_notifications(BackupVaultName=vault_name)
    assert reput["SNSTopicArn"] == topic_arn, (
        f"expected the notification slot to be reusable after delete, got topic {reput['SNSTopicArn']!r}"
    )
    assert sorted(reput["BackupVaultEvents"]) == sorted(events), (
        f"expected the notification slot to be reusable after delete, got events "
        f"{sorted(reput['BackupVaultEvents'])!r}"
    )


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
