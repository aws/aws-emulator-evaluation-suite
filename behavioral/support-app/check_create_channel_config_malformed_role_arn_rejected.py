"""create-channel-config-malformed-role-arn-rejected."""
from __future__ import annotations

import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-channel-config-malformed-role-arn-rejected"
GROUP = "overly-permissive"
SERVICES = ["support-app"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateSlackChannelConfiguration with a channelRoleArn outside the IAM role ARN pattern fails with
    AccessDeniedException "Cross-account pass role is not allowed." (not a ValidationException), the
    configuration is not listed, and ListSlackWorkspaceConfigurations still succeeds."""
    client = ctx.client("support-app")
    sts = ctx.client("sts")

    sts.get_caller_identity()["Account"]
    team_id = f"T{uuid.uuid4().hex[:10].upper()}"
    channel_id = f"C{uuid.uuid4().hex[:10].upper()}"
    malformed_role_arn = "not-an-iam-role-arn-" + uuid.uuid4().hex[:12]

    code, message = _error(
        lambda: client.create_slack_channel_configuration(
            teamId=team_id,
            channelId=channel_id,
            channelRoleArn=malformed_role_arn,
            notifyOnCaseSeverity="none",
        )
    )
    assert code == "AccessDeniedException", f"unexpected code: {code}: {message}"
    assert message == "Cross-account pass role is not allowed.", message

    listed = client.list_slack_channel_configurations().get("slackChannelConfigurations", [])
    assert not any(
        c["teamId"] == team_id and c["channelId"] == channel_id for c in listed
    ), f"channel config for team={team_id} channel={channel_id} exists despite rejection"

    workspaces = client.list_slack_workspace_configurations()
    assert isinstance(workspaces.get("slackWorkspaceConfigurations"), list), (
        f"expected a list from an unrelated read, got {workspaces.get('slackWorkspaceConfigurations')!r}"
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
