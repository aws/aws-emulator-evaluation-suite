"""create-asset-file-rejected-when-artifact-already-has-its-one-file."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-asset-file-rejected-when-artifact-already-has-its-one-file"
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


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:data", "dp:api")
def run(ctx) -> None:
    """An artifact asset holds exactly one file; CreateAssetFile against one that already
    has a file is refused, and the original file is left exactly as it was.
    """
    client = ctx.client("devops-agent")
    space_name = ctx.unique_name("sim2real-behav-devops-agent-space-")
    space_id = client.create_agent_space(name=space_name, tags={"sim2real": "probe"})["agentSpace"]["agentSpaceId"]
    ctx.on_cleanup(_teardown(lambda: client.delete_agent_space(agentSpaceId=space_id), "ResourceNotFoundException"))

    asset_id = client.create_asset(
        agentSpaceId=space_id, assetType="artifact",
        metadata={"title": "probe artifact", "description": "holds exactly one file"},
        content={"file": {"path": "a.txt", "body": {"text": "original"}}},
    )["asset"]["assetId"]
    ctx.on_cleanup(_teardown(lambda: client.delete_asset(agentSpaceId=space_id, assetId=asset_id),
                             "ResourceNotFoundException"))

    code, message = _error(lambda: client.create_asset_file(
        agentSpaceId=space_id, assetId=asset_id, path="b.txt", content={"text": "second"},
    ))
    assert code == "ValidationException", f"expected ValidationException, got {code}: {message!r}"
    assert message == (
        "Assets of type 'artifact' support only one file. Use UpdateAssetFile to replace the existing file."
    ), f"unexpected message {message!r}"

    files = client.list_asset_files(agentSpaceId=space_id, assetId=asset_id)["items"]
    paths = [f["path"] for f in files]
    assert paths == ["a.txt"], f"file set changed after the refused create: {paths!r}"
    original = client.get_asset_file(agentSpaceId=space_id, assetId=asset_id, path="a.txt")
    assert original["file"]["content"]["text"] == "original", (
        f"original file content changed: {original['file']['content']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
