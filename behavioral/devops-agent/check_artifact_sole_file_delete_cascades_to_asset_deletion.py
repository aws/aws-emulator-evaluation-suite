"""artifact-sole-file-delete-cascades-to-asset-deletion."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "artifact-sole-file-delete-cascades-to-asset-deletion"
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


@tags("axis:happy-path", "cap:c1", "concern:representation", "concern:data-plane", "plane:data", "dp:api")
def run(ctx) -> None:
    """Deleting an artifact asset's only file removes the whole asset, not just the file,
    while a sibling artifact in the same space is unaffected.
    """
    client = ctx.client("devops-agent")
    space_name = ctx.unique_name("sim2real-behav-devops-agent-space-")
    space_id = client.create_agent_space(name=space_name, tags={"sim2real": "probe"})["agentSpace"]["agentSpaceId"]
    ctx.on_cleanup(_teardown(lambda: client.delete_agent_space(agentSpaceId=space_id), "ResourceNotFoundException"))

    asset_a = client.create_asset(
        agentSpaceId=space_id, assetType="artifact",
        metadata={"title": "asset A", "description": "the asset whose sole file is deleted"},
        content={"file": {"path": "a.txt", "body": {"text": "content A"}}},
    )["asset"]["assetId"]

    asset_b = client.create_asset(
        agentSpaceId=space_id, assetType="artifact",
        metadata={"title": "asset B", "description": "the positive control, left untouched"},
        content={"file": {"path": "b.txt", "body": {"text": "content B"}}},
    )["asset"]["assetId"]
    ctx.on_cleanup(_teardown(lambda: client.delete_asset(agentSpaceId=space_id, assetId=asset_b),
                             "ResourceNotFoundException"))

    client.delete_asset_file(agentSpaceId=space_id, assetId=asset_a, path="a.txt")

    code, message = _error(lambda: client.get_asset(agentSpaceId=space_id, assetId=asset_a))
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code}: {message!r}"
    assert message == f"Asset not found: {asset_a}", f"unexpected message {message!r}"

    code, message = _error(lambda: client.get_asset_file(agentSpaceId=space_id, assetId=asset_a, path="a.txt"))
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code}: {message!r}"

    control = client.get_asset(agentSpaceId=space_id, assetId=asset_b)
    assert control["asset"]["assetId"] == asset_b, f"control asset missing: {control!r}"
    control_file = client.get_asset_file(agentSpaceId=space_id, assetId=asset_b, path="b.txt")
    assert control_file["file"]["content"]["text"] == "content B", (
        f"control file content changed: {control_file['file']['content']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
