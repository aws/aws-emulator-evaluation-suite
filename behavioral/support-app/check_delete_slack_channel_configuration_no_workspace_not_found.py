"""delete-slack-channel-configuration-no-workspace-not-found."""
from __future__ import annotations

import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-slack-channel-configuration-no-workspace-not-found"
GROUP = "error-semantics"
SERVICES = ["support-app"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteSlackChannelConfiguration for a teamId and channelId with no configuration (and no
    workspace) fails with ResourceNotFoundException and the exact message, nothing is listed for the
    pair, and ListSlackWorkspaceConfigurations still succeeds."""
    client = ctx.client("support-app")

    team_id = f"T{uuid.uuid4().hex[:10].upper()}"
    channel_id = f"C{uuid.uuid4().hex[:10].upper()}"

    code, message = _error(
        lambda: client.delete_slack_channel_configuration(teamId=team_id, channelId=channel_id)
    )
    assert code == "ResourceNotFoundException", f"unexpected code: {code}: {message}"
    assert message == (
        f"Slack channel configuration for team {team_id} and channel {channel_id} not found"
    ), message

    # Positive control: an unrelated, always-valid read still works.
    workspaces = client.list_slack_workspace_configurations()
    got = workspaces.get("slackWorkspaceConfigurations")
    assert isinstance(got, list), f"expected a list of workspace configurations, got {got!r}"

    # Effect absent, independent read at the destination: terminal assertion.
    listed = client.list_slack_channel_configurations().get("slackChannelConfigurations", [])
    assert not any(c["teamId"] == team_id and c["channelId"] == channel_id for c in listed), (
        f"unexpected channel configuration left behind for team={team_id} channel={channel_id}"
    )


def _error(fn):
    """Call fn(); return the (code, message) of its ClientError. An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
