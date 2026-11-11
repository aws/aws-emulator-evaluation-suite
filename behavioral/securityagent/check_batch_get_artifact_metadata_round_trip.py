"""batch-get-artifact-metadata-round-trip."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "batch-get-artifact-metadata-round-trip"
GROUP = "data-plane"
SERVICES = ["securityagent"]


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """BatchGetArtifactMetadata returns metadata (file name) for every artifact id
    requested, matching what was set on AddArtifact."""
    sa = ctx.client("securityagent")
    agent_space_id = sa.create_agent_space(name=ctx.unique_name("sim2real-behav-agentspace-"))["agentSpaceId"]
    ctx.on_cleanup(lambda: sa.delete_agent_space(agentSpaceId=agent_space_id))

    id_one = sa.add_artifact(
        agentSpaceId=agent_space_id, artifactContent=b"one", artifactType="TXT", fileName="one.txt"
    )["artifactId"]
    id_two = sa.add_artifact(
        agentSpaceId=agent_space_id, artifactContent=b"{}", artifactType="JSON", fileName="two.json"
    )["artifactId"]
    ctx.on_cleanup(lambda: sa.delete_artifact(agentSpaceId=agent_space_id, artifactId=id_one))
    ctx.on_cleanup(lambda: sa.delete_artifact(agentSpaceId=agent_space_id, artifactId=id_two))

    result = sa.batch_get_artifact_metadata(agentSpaceId=agent_space_id, artifactIds=[id_one, id_two])
    metadata_list = result["artifactMetadataList"]
    assert len(metadata_list) == 2, f"expected exactly 2 metadata entries, got {len(metadata_list)}: {metadata_list!r}"
    by_id = {m["artifactId"]: m for m in metadata_list}
    assert by_id[id_one]["fileName"] == "one.txt", f"expected fileName 'one.txt', got {by_id[id_one]['fileName']!r}"
    assert by_id[id_two]["fileName"] == "two.json", f"expected fileName 'two.json', got {by_id[id_two]['fileName']!r}"
    assert by_id[id_one]["agentSpaceId"] == agent_space_id, (
        f"expected agentSpaceId {agent_space_id!r} on id_one entry, got {by_id[id_one]['agentSpaceId']!r}"
    )
    assert by_id[id_two]["agentSpaceId"] == agent_space_id, (
        f"expected agentSpaceId {agent_space_id!r} on id_two entry, got {by_id[id_two]['agentSpaceId']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
