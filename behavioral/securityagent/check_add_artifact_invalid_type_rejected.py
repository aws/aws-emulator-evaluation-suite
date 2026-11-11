"""add-artifact-invalid-type-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "add-artifact-invalid-type-rejected"
GROUP = "overly-permissive"
SERVICES = ["securityagent"]


def _error(fn):
    """Call fn(); return its botocore (code, message). An unexpected SUCCESS raises, because an
    emulator ACCEPTING input real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


@tags("axis:rejection", "cap:c1", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """AddArtifact with an artifactType outside the documented enum is refused server-side with
    ValidationException and its exact message, and leaves no artifact behind; a TXT artifact in the
    same agent space still uploads and is the only one listed."""
    sa = ctx.client("securityagent")

    agent_space_id = sa.create_agent_space(name=ctx.unique_name("sim2real-behav-agentspace-"))["agentSpaceId"]
    ctx.on_cleanup(lambda: sa.delete_agent_space(agentSpaceId=agent_space_id))

    code, message = _error(
        lambda: sa.add_artifact(
            agentSpaceId=agent_space_id,
            artifactContent=b"malware.exe",
            artifactType="EXE",
            fileName="bad.exe",
        )
    )
    assert code == "ValidationException", f"expected ValidationException for artifactType=EXE, got {code!r}"
    expected = (
        "1 validation error detected: Value 'EXE' at 'artifactType' failed to satisfy constraint: "
        "Member must satisfy enum value set: [DOCX, YAML, JSON, JPEG, PNG, TXT, PDF, MD, DOC]"
    )
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # effect absent: nothing was created by the rejected call
    after_reject = sa.list_artifacts(agentSpaceId=agent_space_id)["artifactSummaries"]
    assert after_reject == [], f"expected no artifacts after rejected AddArtifact, found {after_reject!r}"

    # positive control: a validly typed artifact in the same agent space still succeeds
    valid_id = sa.add_artifact(
        agentSpaceId=agent_space_id, artifactContent=b"ok", artifactType="TXT", fileName="good.txt"
    )["artifactId"]
    ctx.on_cleanup(lambda: sa.delete_artifact(agentSpaceId=agent_space_id, artifactId=valid_id))

    listed = sa.list_artifacts(agentSpaceId=agent_space_id)["artifactSummaries"]
    listed_ids = {a["artifactId"] for a in listed}
    assert listed_ids == {valid_id}, f"expected only {valid_id!r} listed, got {listed_ids!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

