"""delete-slack-workspace-configuration-malformed-team-id-invalid."""
from __future__ import annotations

import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-slack-workspace-configuration-malformed-team-id-invalid"
GROUP = "error-semantics"
SERVICES = ["support-app"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteSlackWorkspaceConfiguration with a teamId violating the ^\\S+$ pattern fails with
    ValidationException, while a well-formed but unregistered teamId fails with
    ResourceNotFoundException, each with the exact message: syntax is validated before lookup."""
    client = ctx.client("support-app")

    valid_team_id = f"T{uuid.uuid4().hex[:12].upper()}"
    control_code, control_message = _error(
        lambda: client.delete_slack_workspace_configuration(teamId=valid_team_id)
    )
    assert control_code == "ResourceNotFoundException", (
        f"positive control: a syntactically valid, never-registered teamId "
        f"must reach the lookup and get ResourceNotFoundException, got {control_code}: {control_message}"
    )
    assert control_message == f"Slack workspace configuration for team {valid_team_id} not found", (
        control_message
    )

    malformed_team_id = "  "

    code, message = _error(
        lambda: client.delete_slack_workspace_configuration(teamId=malformed_team_id)
    )
    assert code == "ValidationException", f"unexpected code: {code}: {message}"
    assert message == (
        f"1 validation error detected: Value '{malformed_team_id}' at 'teamId' failed to satisfy "
        "constraint: Member must satisfy regular expression pattern: \\S+"
    ), message


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
