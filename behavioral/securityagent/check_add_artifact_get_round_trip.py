"""add-artifact-get-round-trip."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "add-artifact-get-round-trip"
GROUP = "data-plane"
SERVICES = ["securityagent"]


def _error(fn):
    """Call fn(); return its botocore (code, message). An unexpected success raises."""
    try:
        fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError("expected a ClientError, call succeeded")


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """GetArtifact returns the exact bytes, file name and type TXT that AddArtifact stored; after
    DeleteArtifact, GetArtifact answers ResourceNotFoundException "No artifact was found for id: <id>",
    and a second DeleteArtifact on the same id succeeds."""
    sa = ctx.client("securityagent")
    agent_space_id = sa.create_agent_space(name=ctx.unique_name("sim2real-behav-agentspace-"))["agentSpaceId"]
    ctx.on_cleanup(lambda: sa.delete_agent_space(agentSpaceId=agent_space_id))

    content = b"hello from sim2real behavioral check\nline two\n"
    file_name = "notes.txt"
    added = sa.add_artifact(
        agentSpaceId=agent_space_id,
        artifactContent=content,
        artifactType="TXT",
        fileName=file_name,
    )
    artifact_id = added["artifactId"]
    ctx.on_cleanup(lambda: sa.delete_artifact(agentSpaceId=agent_space_id, artifactId=artifact_id))

    got = sa.get_artifact(agentSpaceId=agent_space_id, artifactId=artifact_id)
    assert got["fileName"] == file_name, f"fileName mismatch: expected {file_name!r}, got {got['fileName']!r}"
    assert got["artifact"]["type"] == "TXT", f"artifact type mismatch: expected TXT, got {got['artifact']['type']!r}"
    contents = got["artifact"]["contents"]
    if isinstance(contents, (bytes, bytearray)):
        assert bytes(contents) == content, f"byte contents mismatch: {contents!r}"
    else:
        # GetArtifact returns the raw bytes base64-encoded as a string
        import base64

        assert base64.b64decode(contents) == content, f"base64 contents mismatch: {contents!r}"

    sa.delete_artifact(agentSpaceId=agent_space_id, artifactId=artifact_id)

    code, message = _error(lambda: sa.get_artifact(agentSpaceId=agent_space_id, artifactId=artifact_id))
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code!r}"
    expected = f"No artifact was found for id: {artifact_id}"
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # DeleteArtifact is idempotent: deleting an already-deleted artifact id succeeds, it
    # does not raise ResourceNotFoundException.
    sa.delete_artifact(agentSpaceId=agent_space_id, artifactId=artifact_id)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
