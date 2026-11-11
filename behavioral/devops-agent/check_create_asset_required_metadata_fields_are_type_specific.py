"""create-asset-required-metadata-fields-are-type-specific."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-asset-required-metadata-fields-are-type-specific"
GROUP = 'asset-lifecycle'
SERVICES = ['devops-agent']


def _error(fn):
    """(Error.Code, Error.Message) of the ClientError fn() raises; an unexpected success fails."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


def _teardown(undo, *not_found: str):
    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:data", "dp:api")
def run(ctx) -> None:
    """CreateAsset enforces a required metadata field whose name is specific to the assetType
    requested, a business rule the model's bare metadata document cannot express.
    """
    client = ctx.client("devops-agent")
    space_name = ctx.unique_name("sim2real-behav-devops-agent-space-")
    space_id = client.create_agent_space(name=space_name, tags={"sim2real": "probe"})["agentSpace"]["agentSpaceId"]
    ctx.on_cleanup(_teardown(lambda: client.delete_agent_space(agentSpaceId=space_id), "ResourceNotFoundException"))

    created = client.create_asset(
        agentSpaceId=space_id, assetType="artifact",
        metadata={"title": "probe artifact", "description": "the positive control"},
        content={"file": {"path": "a.txt", "body": {"text": "content"}}},
    )
    asset_id = created["asset"]["assetId"]
    assert created["asset"]["assetType"] == "artifact", f"control asset has wrong type: {created['asset']!r}"
    ctx.on_cleanup(_teardown(lambda: client.delete_asset(agentSpaceId=space_id, assetId=asset_id),
                             "ResourceNotFoundException"))

    code, message = _error(lambda: client.create_asset(
        agentSpaceId=space_id, assetType="skill", metadata={},
        content={"file": {"path": "SKILL.md", "body": {"text": "# skill"}}},
    ))
    assert code == "ValidationException", f"expected ValidationException, got {code}: {message!r}"
    assert message == "name is required for Skill knowledge items", f"unexpected message {message!r}"

    code, message = _error(lambda: client.create_asset(
        agentSpaceId=space_id, assetType="artifact", metadata={},
        content={"file": {"path": "data.json", "body": {"text": "{}"}}},
    ))
    assert code == "ValidationException", f"expected ValidationException, got {code}: {message!r}"
    assert message == "title is required for Artifact knowledge items", f"unexpected message {message!r}"

    code, message = _error(lambda: client.create_asset(
        agentSpaceId=space_id, assetType="attachment", metadata={},
        content={"file": {"path": "notes.txt", "body": {"text": "notes"}}},
    ))
    assert code == "ValidationException", f"expected ValidationException, got {code}: {message!r}"
    assert message == "filename is required for Attachment knowledge items", f"unexpected message {message!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
