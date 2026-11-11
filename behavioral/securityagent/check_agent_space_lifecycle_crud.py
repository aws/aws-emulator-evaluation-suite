"""agent-space-lifecycle-crud."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "agent-space-lifecycle-crud"
GROUP = "state"
SERVICES = ["securityagent"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateAgentSpace persists name/description, BatchGetAgentSpaces reflects it, and
    DeleteAgentSpace makes it unretrievable (reported in `notFound`) and unusable (a
    second delete on the dead id is rejected with ResourceNotFoundException)."""
    sa = ctx.client("securityagent")
    name = ctx.unique_name("sim2real-behav-agentspace-")

    created = sa.create_agent_space(
        name=name,
        description="a test agent space",
        tags={"sim2real:managed": "true", "sim2real:check": CHECK},
    )
    agent_space_id = created["agentSpaceId"]
    assert created["name"] == name, f"expected created name {name!r}, got {created['name']!r}"

    def _cleanup():
        try:
            sa.delete_agent_space(agentSpaceId=agent_space_id)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise

    ctx.on_cleanup(_cleanup)

    got = sa.batch_get_agent_spaces(agentSpaceIds=[agent_space_id])
    assert got["notFound"] == [], f"expected no notFound entries, got {got['notFound']!r}"
    assert len(got["agentSpaces"]) == 1, f"expected exactly 1 agent space, got {len(got['agentSpaces'])}"
    assert got["agentSpaces"][0]["name"] == name, (
        f"expected agent space name {name!r}, got {got['agentSpaces'][0]['name']!r}"
    )
    assert got["agentSpaces"][0]["description"] == "a test agent space", (
        f"expected description 'a test agent space', got {got['agentSpaces'][0]['description']!r}"
    )

    sa.delete_agent_space(agentSpaceId=agent_space_id)

    after = sa.batch_get_agent_spaces(agentSpaceIds=[agent_space_id])
    assert after["agentSpaces"] == [], f"expected no agent spaces after delete, got {after['agentSpaces']!r}"
    assert after["notFound"] == [agent_space_id], (
        f"expected notFound == [{agent_space_id!r}], got {after['notFound']!r}"
    )

    try:
        sa.delete_agent_space(agentSpaceId=agent_space_id)
        raise AssertionError("expected ResourceNotFoundException deleting an already-deleted agent space")
    except ClientError as e:
        code = e.response["Error"]["Code"]
        assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code!r}"
        message = e.response["Error"].get("Message")
        expected = "The specified agent instance does not exist."
        assert message == expected, f"expected message {expected!r}, got {message!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
