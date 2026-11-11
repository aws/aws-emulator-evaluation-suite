"""create-slack-channel-configuration-no-workspace-rejected."""
from __future__ import annotations

import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-slack-channel-configuration-no-workspace-rejected"
GROUP = "overly-permissive"
SERVICES = ["support-app"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateSlackChannelConfiguration for a teamId with no registered Slack workspace fails with
    ConflictException "Workspace installation not found for account <account> and team <team>", and
    the configuration is not listed; ListSlackWorkspaceConfigurations returns a list."""
    client = ctx.client("support-app")
    sts = ctx.client("sts")

    account_id = sts.get_caller_identity()["Account"]
    team_id = f"T{uuid.uuid4().hex[:10].upper()}"
    channel_id = f"C{uuid.uuid4().hex[:10].upper()}"
    role_arn = f"arn:aws:iam::{account_id}:role/sim2real-behav-{uuid.uuid4().hex[:8]}"

    # Safety net: if this environment unexpectedly already has a matching
    # workspace and the create succeeds, still clean it up.
    ctx.on_cleanup(lambda: _delete_channel_config_ignore_not_found(client, team_id, channel_id))

    # Positive control: an unrelated, always-valid read works before we ever
    # attempt the rejected call, so the check cannot pass merely because
    # everything is denied.
    workspaces = client.list_slack_workspace_configurations()
    workspace_list = workspaces.get("slackWorkspaceConfigurations")
    assert isinstance(workspace_list, list), f"expected a list, got {workspace_list!r}"

    code, message = _error(
        lambda: client.create_slack_channel_configuration(
            teamId=team_id,
            channelId=channel_id,
            channelRoleArn=role_arn,
            notifyOnCaseSeverity="none",
        )
    )
    assert code == "ConflictException", f"unexpected code: {code}: {message}"
    assert message == f"Workspace installation not found for account {account_id} and team {team_id}", message

    # Effect absent: no configuration was created for this channel -- the
    # independent, terminal read.
    listed = client.list_slack_channel_configurations().get("slackChannelConfigurations", [])
    assert not any(c["teamId"] == team_id and c["channelId"] == channel_id for c in listed), (
        f"channel config for team={team_id} channel={channel_id} unexpectedly present: {listed}"
    )


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
