"""delete-nonexistent-slack-workspace-configuration-not-found."""
from __future__ import annotations

import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-nonexistent-slack-workspace-configuration-not-found"
GROUP = "error-semantics"
SERVICES = ["support-app"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteSlackWorkspaceConfiguration for a teamId that was never registered
    is rejected with ResourceNotFoundException, and an unrelated list call
    still succeeds in the same run."""
    client = ctx.client("support-app")

    team_id = f"T{uuid.uuid4().hex[:12].upper()}"

    before = client.list_slack_workspace_configurations().get("slackWorkspaceConfigurations", [])
    assert not any(w["teamId"] == team_id for w in before), (
        f"expected no config for freshly generated team_id={team_id}, found one in {before!r}"
    )

    code, message = _error(lambda: client.delete_slack_workspace_configuration(teamId=team_id))
    assert code == "ResourceNotFoundException", f"unexpected code: {code}: {message}"
    assert message == f"Slack workspace configuration for team {team_id} not found", message

    after = client.list_slack_workspace_configurations().get("slackWorkspaceConfigurations", [])
    assert not any(w["teamId"] == team_id for w in after), (
        f"expected no config for team_id={team_id} after the rejected delete, found one in {after!r}"
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
