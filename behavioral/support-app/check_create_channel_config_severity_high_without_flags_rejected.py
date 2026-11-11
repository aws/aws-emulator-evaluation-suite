"""create-channel-config-severity-high-without-flags-rejected."""
from __future__ import annotations

import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-channel-config-severity-high-without-flags-rejected"
GROUP = "overly-permissive"
SERVICES = ["support-app"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateSlackChannelConfiguration with notifyOnCaseSeverity high and all three notify flags off fails
    with ValidationException and the exact message, while the same call with one flag on clears that
    rule and fails ConflictException for the unregistered workspace; nothing is created."""
    client = ctx.client("support-app")
    sts = ctx.client("sts")

    account_id = sts.get_caller_identity()["Account"]
    role_arn = f"arn:aws:iam::{account_id}:role/sim2real-behav-{uuid.uuid4().hex[:8]}"

    control_team_id = f"T{uuid.uuid4().hex[:10].upper()}"
    control_channel_id = f"C{uuid.uuid4().hex[:10].upper()}"

    # Safety net: if this environment unexpectedly already has a matching
    # workspace and the positive control succeeds, still clean it up.
    ctx.on_cleanup(
        lambda: _delete_channel_config_ignore_not_found(client, control_team_id, control_channel_id)
    )

    # Positive control: the same call shape, with one notification flag true.
    # This clears the severity/flags business rule under test, so the
    # request is rejected for a different, unrelated reason (no Slack
    # workspace registered for this teamId) rather than ValidationException.
    control_code, control_message = _error(
        lambda: client.create_slack_channel_configuration(
            teamId=control_team_id,
            channelId=control_channel_id,
            channelRoleArn=role_arn,
            notifyOnCaseSeverity="high",
            notifyOnAddCorrespondenceToCase=False,
            notifyOnCreateOrReopenCase=True,
            notifyOnResolveCase=False,
        )
    )
    assert control_code == "ConflictException", f"unexpected code: {control_code}: {control_message}"
    assert control_message == (
        f"Workspace installation not found for account {account_id} and team {control_team_id}"
    ), control_message

    team_id = f"T{uuid.uuid4().hex[:10].upper()}"
    channel_id = f"C{uuid.uuid4().hex[:10].upper()}"

    code, message = _error(
        lambda: client.create_slack_channel_configuration(
            teamId=team_id,
            channelId=channel_id,
            channelRoleArn=role_arn,
            notifyOnCaseSeverity="high",
            notifyOnAddCorrespondenceToCase=False,
            notifyOnCreateOrReopenCase=False,
            notifyOnResolveCase=False,
        )
    )
    assert code == "ValidationException", f"unexpected code: {code}: {message}"
    assert message == (
        "Your CreateSlackChannelConfiguration request isn't valid. If NotifyOnCaseSeverity is all "
        "or high, you must enter true for at least one of the following parameters: "
        "NotifyOnCreateOrReopenCase, NotifyOnAddCorrespondenceToCase or NotifyOnResolveCase. "
        "Try your request again."
    ), message

    listed = client.list_slack_channel_configurations().get("slackChannelConfigurations", [])
    assert not any(
        c["teamId"] in (team_id, control_team_id) and c["channelId"] in (channel_id, control_channel_id)
        for c in listed
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
