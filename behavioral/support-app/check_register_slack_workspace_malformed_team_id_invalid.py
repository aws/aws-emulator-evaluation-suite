"""register-slack-workspace-malformed-team-id-invalid."""
from __future__ import annotations

import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "register-slack-workspace-malformed-team-id-invalid"
GROUP = "error-semantics"
SERVICES = ["support-app"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """RegisterSlackWorkspaceForOrganization with a whitespace-only teamId fails with ValidationException
    and the exact message, while a well-formed but never-authorized teamId fails with
    ResourceNotFoundException."""
    client = ctx.client("support-app")

    malformed_team_id = "   "

    code, message = _error(
        lambda: client.register_slack_workspace_for_organization(teamId=malformed_team_id)
    )
    assert code == "ValidationException", f"unexpected code: {code}: {message}"
    assert message == (
        f"1 validation error detected: Value '{malformed_team_id}' at 'teamId' failed to satisfy "
        "constraint: Member must satisfy regular expression pattern: \\S+"
    ), message

    # Positive control: the same operation, given a syntactically-valid but
    # never-authorized teamId, is rejected for a DIFFERENT, specific reason --
    # proving the ValidationException above is not a blanket refusal of every
    # call to this operation.
    valid_team_id = f"T{uuid.uuid4().hex[:10].upper()}"
    code2, message2 = _error(
        lambda: client.register_slack_workspace_for_organization(teamId=valid_team_id)
    )
    # message varies: it names the organization's management account, which depends on the
    # caller's account topology and is not a value the check creates or reads from ctx.
    assert code2 == "ResourceNotFoundException", f"unexpected code: {code2}: {message2}"


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
