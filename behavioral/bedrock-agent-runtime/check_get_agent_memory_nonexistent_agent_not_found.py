"""get-agent-memory-nonexistent-agent-not-found."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "get-agent-memory-nonexistent-agent-not-found"
GROUP = "error-semantics"
SERVICES = ["bedrock-agent-runtime"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """GetAgentMemory for a never-created agent and alias gets ResourceNotFoundException "Agent or Alias
    not found."."""
    client = ctx.client("bedrock-agent-runtime")

    result, message = _call(
        lambda: client.get_agent_memory(
            agentId="0000000000",
            agentAliasId="1111111111",
            memoryType="SESSION_SUMMARY",
            memoryId="test-memory-id",
        )
    )
    assert result == "ResourceNotFoundException", (
        f"expected GetAgentMemory on a never-created agent/alias to raise "
        f"ResourceNotFoundException, got {result!r}"
    )
    assert message == "Agent or Alias not found.", f"unexpected message: {message!r}"


def _call(fn):
    """Call fn() and return its error (code, message); raise AssertionError if the call succeeds."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
