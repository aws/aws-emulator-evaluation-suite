"""update-slack-channel-configuration-no-workspace-not-found."""
from __future__ import annotations

import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-slack-channel-configuration-no-workspace-not-found"
GROUP = "error-semantics"
SERVICES = ["support-app"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """UpdateSlackChannelConfiguration with a malformed teamId fails with ValidationException, and with a
    well-formed pair that has no configuration fails with ResourceNotFoundException, each with the
    exact message; nothing is listed for the pair and ListSlackWorkspaceConfigurations succeeds."""
    client = ctx.client("support-app")

    channel_id = f"C{uuid.uuid4().hex[:10].upper()}"

    # Distinguishing control: a syntactically invalid teamId (violates the
    # ^\S+$ pattern) is rejected for a different, specific reason than the
    # main case below -- proving the target does not return the same code
    # for every call regardless of input.
    control_code, control_message = _error(
        lambda: client.update_slack_channel_configuration(
            teamId="   ",
            channelId=channel_id,
            notifyOnCaseSeverity="none",
        )
    )
    assert control_code == "ValidationException", f"unexpected code: {control_code}: {control_message}"
    assert control_message == (
        "1 validation error detected: Value '   ' at 'teamId' failed to satisfy constraint: "
        "Member must satisfy regular expression pattern: \\S+"
    ), control_message

    team_id = f"T{uuid.uuid4().hex[:10].upper()}"

    code, message = _error(
        lambda: client.update_slack_channel_configuration(
            teamId=team_id,
            channelId=channel_id,
            notifyOnCaseSeverity="none",
        )
    )
    assert code == "ResourceNotFoundException", f"unexpected code: {code}: {message}"
    assert message == (
        f"Slack channel configuration for team {team_id} and channel {channel_id} not found"
    ), message
    assert code != control_code, "same code for malformed input and a missing resource"

    listed = client.list_slack_channel_configurations().get("slackChannelConfigurations", [])
    assert not any(c["teamId"] == team_id and c["channelId"] == channel_id for c in listed)

    workspaces = client.list_slack_workspace_configurations()
    assert isinstance(workspaces.get("slackWorkspaceConfigurations"), list)


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
