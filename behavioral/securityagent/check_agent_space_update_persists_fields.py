"""agent-space-update-persists-fields."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "agent-space-update-persists-fields"
GROUP = "state"
SERVICES = ["securityagent"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateAgentSpace changes to name/description are durable and visible afterward, and
    DeleteAgentSpace afterward makes the updated agent space unretrievable (reported in
    `notFound`)."""
    sa = ctx.client("securityagent")
    name = ctx.unique_name("sim2real-behav-agentspace-")
    agent_space_id = sa.create_agent_space(
        name=name, description="before", tags={"sim2real": "behavioral"}
    )["agentSpaceId"]

    def _cleanup():
        try:
            sa.delete_agent_space(agentSpaceId=agent_space_id)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise

    ctx.on_cleanup(_cleanup)

    new_name = ctx.unique_name("sim2real-behav-agentspace-renamed-")
    sa.update_agent_space(agentSpaceId=agent_space_id, name=new_name, description="after")

    before_delete = sa.batch_get_agent_spaces(agentSpaceIds=[agent_space_id])
    assert before_delete["notFound"] == [], (
        f"expected the updated agent space to still resolve, got notFound={before_delete['notFound']}"
    )
    got = before_delete["agentSpaces"][0]
    assert got["name"] == new_name, f"expected name={new_name!r}, got {got['name']!r}"
    assert got["description"] == "after", f"expected description='after', got {got['description']!r}"

    sa.delete_agent_space(agentSpaceId=agent_space_id)

    after_delete = sa.batch_get_agent_spaces(agentSpaceIds=[agent_space_id])
    assert after_delete["agentSpaces"] == [], (
        f"expected no agent spaces after delete, got {after_delete['agentSpaces']}"
    )
    assert after_delete["notFound"] == [agent_space_id], (
        f"expected notFound=[{agent_space_id}], got {after_delete['notFound']}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
