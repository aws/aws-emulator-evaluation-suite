"""list-artifacts-reflects-additions-and-deletions."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "list-artifacts-reflects-additions-and-deletions"
GROUP = "state"
SERVICES = ["securityagent"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListArtifacts lists exactly the two added artifacts, then only the remaining one after a delete;
    GetArtifact on the deleted id answers ResourceNotFoundException with its exact message, and a
    second DeleteArtifact on it returns 200."""
    sa = ctx.client("securityagent")
    agent_space_id = sa.create_agent_space(name=ctx.unique_name("sim2real-behav-agentspace-"))["agentSpaceId"]
    ctx.on_cleanup(lambda: sa.delete_agent_space(agentSpaceId=agent_space_id))

    id_one = sa.add_artifact(
        agentSpaceId=agent_space_id, artifactContent=b"one", artifactType="TXT", fileName="one.txt"
    )["artifactId"]
    id_two = sa.add_artifact(
        agentSpaceId=agent_space_id, artifactContent=b"two", artifactType="TXT", fileName="two.txt"
    )["artifactId"]
    ctx.on_cleanup(lambda: sa.delete_artifact(agentSpaceId=agent_space_id, artifactId=id_two))

    listed = sa.list_artifacts(agentSpaceId=agent_space_id)["artifactSummaries"]
    assert {a["artifactId"] for a in listed} == {id_one, id_two}, (
        f"expected both artifacts listed right after adding them, got {[a['artifactId'] for a in listed]}"
    )

    sa.delete_artifact(agentSpaceId=agent_space_id, artifactId=id_one)

    after = sa.list_artifacts(agentSpaceId=agent_space_id)["artifactSummaries"]
    assert {a["artifactId"] for a in after} == {id_two}, (
        f"expected only the surviving artifact listed after the delete, got {[a['artifactId'] for a in after]}"
    )

    try:
        sa.get_artifact(agentSpaceId=agent_space_id, artifactId=id_one)
        raise AssertionError("GetArtifact on a deleted artifact unexpectedly succeeded")
    except ClientError as e:
        code = e.response["Error"]["Code"]
        assert code == "ResourceNotFoundException", (
            f"expected ResourceNotFoundException reading the deleted artifact, got {code}"
        )
        message = e.response["Error"].get("Message")
        expected = f"No artifact was found for id: {id_one}"
        assert message == expected, f"expected message {expected!r}, got {message!r}"

    # DeleteArtifact on an already-deleted id is idempotent, not a ResourceNotFoundException.
    second_delete = sa.delete_artifact(agentSpaceId=agent_space_id, artifactId=id_one)
    status = second_delete["ResponseMetadata"]["HTTPStatusCode"]
    assert status == 200, f"expected a repeat DeleteArtifact to be idempotent (200), got {status}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
