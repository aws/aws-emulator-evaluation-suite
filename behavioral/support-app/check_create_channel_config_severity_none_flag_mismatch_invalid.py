"""create-channel-config-severity-none-flag-mismatch-invalid."""
from __future__ import annotations

import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-channel-config-severity-none-flag-mismatch-invalid"
GROUP = "error-semantics"
SERVICES = ["support-app"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateSlackChannelConfiguration rejects notifyOnCaseSeverity='none' when
    one of the notification flags is set true -- the inverse of the 'high'
    business rule. The configuration is never created."""
    client = ctx.client("support-app")
    sts = ctx.client("sts")

    account_id = sts.get_caller_identity()["Account"]
    team_id = f"T{uuid.uuid4().hex[:10].upper()}"
    channel_id = f"C{uuid.uuid4().hex[:10].upper()}"
    role_arn = f"arn:aws:iam::{account_id}:role/sim2real-behav-{uuid.uuid4().hex[:8]}"

    # Safety net: if this environment unexpectedly already has a matching
    # workspace and the create succeeds, still clean it up.
    ctx.on_cleanup(lambda: _delete_channel_config_ignore_not_found(client, team_id, channel_id))

    code, message = _error(
        lambda: client.create_slack_channel_configuration(
            teamId=team_id,
            channelId=channel_id,
            channelRoleArn=role_arn,
            notifyOnCaseSeverity="none",
            notifyOnCreateOrReopenCase=True,
        )
    )
    assert code == "ValidationException", f"unexpected code: {code}: {message}"
    assert message == (
        "Your CreateSlackChannelConfiguration request isn't valid. If NotifyOnCaseSeverity is "
        "none, the following parameters must be null or false: NotifyOnCreateOrReopenCase, "
        "NotifyOnAddCorrespondenceToCase or NotifyOnResolveCase. Try your request again."
    ), message

    listed = client.list_slack_channel_configurations().get("slackChannelConfigurations", [])
    assert not any(
        c["teamId"] == team_id and c["channelId"] == channel_id for c in listed
    ), f"channel config {team_id}/{channel_id} should not have been created"

    # Positive control: an unrelated, always-valid read still works.
    workspaces = client.list_slack_workspace_configurations()
    assert isinstance(workspaces.get("slackWorkspaceConfigurations"), list)


def _error(fn):
    """Call fn(); return the (code, message) of its ClientError. An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


def _delete_channel_config_ignore_not_found(client, team_id, channel_id) -> None:
    try:
        client.delete_slack_channel_configuration(teamId=team_id, channelId=channel_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
