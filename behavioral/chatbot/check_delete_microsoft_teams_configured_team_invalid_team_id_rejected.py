"""delete-microsoft-teams-configured-team-invalid-team-id-rejected."""
from __future__ import annotations

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "delete-microsoft-teams-configured-team-invalid-team-id-rejected"
GROUP = "overly-permissive"
SERVICES = ["chatbot"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteMicrosoftTeamsConfiguredTeam with a 36-character non-UUID TeamId fails with InvalidRequestException
    "Invalid request body" (not the modeled InvalidParameterException), the configured-teams count is unchanged,
    and a custom action created in the same run is readable."""
    chatbot = ctx.client("chatbot")
    bad_team_id = "1" * 36  # right length (36), wrong shape (no hyphens / not hex-UUID)

    before = chatbot.list_microsoft_teams_configured_teams()["ConfiguredTeams"]

    code, message = _error_info(lambda: chatbot.delete_microsoft_teams_configured_team(TeamId=bad_team_id))
    assert code == "InvalidRequestException", f"unexpected code={code!r}"
    assert message == "Invalid request body", f"unexpected message={message!r}"

    after = chatbot.list_microsoft_teams_configured_teams()["ConfiguredTeams"]
    assert len(after) == len(before), "rejected delete unexpectedly changed the configured-teams list"

    # Positive control: a normal, well-formed Chatbot resource lifecycle still works.
    action_name = ctx.unique_name("sim2realteamsctl").replace("-", "")[:64]
    action_arn = chatbot.create_custom_action(
        ActionName=action_name,
        Definition={"CommandText": "echo control"},
        Tags=[{"TagKey": "sim2real", "TagValue": "audit"}],
    )["CustomActionArn"]
    ctx.on_cleanup(lambda: _safe_delete(ctx, action_arn))
    got = chatbot.get_custom_action(CustomActionArn=action_arn)["CustomAction"]
    assert got["CustomActionArn"] == action_arn, (
        f"positive control broken: expected CustomActionArn={action_arn!r}, got={got!r}"
    )


def _safe_delete(ctx, arn: str) -> None:
    chatbot = ctx.client("chatbot")
    try:
        chatbot.delete_custom_action(CustomActionArn=arn)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _error_info(fn):
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
