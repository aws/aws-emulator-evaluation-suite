"""batch-get-agent-spaces-partial-not-found."""
from __future__ import annotations

import uuid

from behavioral_harness import tags

CHECK = "batch-get-agent-spaces-partial-not-found"
GROUP = "error-semantics"
SERVICES = ["securityagent"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """BatchGetAgentSpaces mixing a real id with a well-formed-but-nonexistent one returns
    the real one in `agentSpaces` and the bogus one in `notFound`, never raising a
    whole-call error."""
    sa = ctx.client("securityagent")
    name = ctx.unique_name("sim2real-behav-agentspace-")
    agent_space_id = sa.create_agent_space(name=name, tags={"sim2real": "behavioral"})["agentSpaceId"]
    ctx.on_cleanup(lambda: sa.delete_agent_space(agentSpaceId=agent_space_id))

    # agent space IDs must match (ai|as)-[a-zA-Z0-9-]{1,64}; use that shape but a random
    # value that cannot exist, rather than the sim2real-prefixed name (which doesn't match
    # the required ID pattern and would be rejected client-side as ValidationException).
    bogus_id = f"as-sim2real-{uuid.uuid4().hex}"
    result = sa.batch_get_agent_spaces(agentSpaceIds=[agent_space_id, bogus_id])

    assert bogus_id in result["notFound"], f"expected {bogus_id} in notFound, got {result['notFound']}"
    found_by_id = {a["agentSpaceId"]: a for a in result["agentSpaces"]}
    assert set(found_by_id) == {agent_space_id}, (
        f"expected only {agent_space_id} in agentSpaces, got {set(found_by_id)}"
    )
    assert found_by_id[agent_space_id]["name"] == name, (
        f"expected name {name!r}, got {found_by_id[agent_space_id]['name']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

