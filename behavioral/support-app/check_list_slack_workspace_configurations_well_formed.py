"""list-slack-workspace-configurations-well-formed."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "list-slack-workspace-configurations-well-formed"
GROUP = "control-plane"
SERVICES = ["support-app"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListSlackWorkspaceConfigurations succeeds and returns a well-formed
    response: a list under slackWorkspaceConfigurations where every entry
    carries the documented required fields with the correct types."""
    client = ctx.client("support-app")

    resp = client.list_slack_workspace_configurations()
    workspaces = resp.get("slackWorkspaceConfigurations")
    assert isinstance(workspaces, list), (
        f"expected slackWorkspaceConfigurations to be a list, got {type(workspaces).__name__}: {workspaces!r}"
    )

    for ws in workspaces:
        # teamId is the only required member of SlackWorkspaceConfiguration.
        team_id = ws.get("teamId")
        assert isinstance(team_id, str) and team_id, (
            f"expected non-empty string teamId, got {team_id!r} in entry {ws!r}"
        )
        if "teamName" in ws:
            assert isinstance(ws["teamName"], str), (
                f"expected string teamName, got {ws['teamName']!r} in entry {ws!r}"
            )
        if "allowOrganizationMemberAccount" in ws:
            assert isinstance(ws["allowOrganizationMemberAccount"], bool), (
                f"expected bool allowOrganizationMemberAccount, got "
                f"{ws['allowOrganizationMemberAccount']!r} in entry {ws!r}"
            )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
