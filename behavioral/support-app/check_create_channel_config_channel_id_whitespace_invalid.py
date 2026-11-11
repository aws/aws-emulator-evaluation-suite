"""create-channel-config-channel-id-whitespace-invalid."""
from __future__ import annotations

import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-channel-config-channel-id-whitespace-invalid"
GROUP = "error-semantics"
SERVICES = ["support-app"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateSlackChannelConfiguration rejects a channelId containing whitespace
    (violates the ^\\S+$ pattern) with ValidationException even though it
    satisfies the length constraint, and the configuration is never created."""
    client = ctx.client("support-app")
    sts = ctx.client("sts")

    account_id = sts.get_caller_identity()["Account"]
    team_id = f"T{uuid.uuid4().hex[:10].upper()}"
    channel_id_with_space = "C 12345"
    role_arn = f"arn:aws:iam::{account_id}:role/sim2real-behav-{uuid.uuid4().hex[:8]}"

    code, message = _error(
        lambda: client.create_slack_channel_configuration(
            teamId=team_id,
            channelId=channel_id_with_space,
            channelRoleArn=role_arn,
            notifyOnCaseSeverity="none",
        )
    )
    assert code == "ValidationException", f"unexpected code: {code}: {message}"
    assert message == (
        f"1 validation error detected: Value '{channel_id_with_space}' at 'channelId' failed to "
        "satisfy constraint: Member must satisfy regular expression pattern: \\S+"
    ), message

    listed = client.list_slack_channel_configurations().get("slackChannelConfigurations", [])
    assert not any(c["teamId"] == team_id for c in listed), (
        f"expected no configuration for {team_id!r} to exist, but found one in {listed!r}"
    )

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


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
