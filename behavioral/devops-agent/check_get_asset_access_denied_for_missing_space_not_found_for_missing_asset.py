"""get-asset-access-denied-for-missing-space-not-found-for-missing-asset."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-asset-access-denied-for-missing-space-not-found-for-missing-asset"
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
    """GetAsset tells two distinct causes apart: a space that was never created is a fail-closed
    AccessDenied, while an asset missing from a real space is a specific ResourceNotFound.
    """
    client = ctx.client("devops-agent")
    space_name = ctx.unique_name("sim2real-behav-devops-agent-space-")
    space_id = client.create_agent_space(name=space_name, tags={"sim2real": "probe"})["agentSpace"]["agentSpaceId"]
    ctx.on_cleanup(_teardown(lambda: client.delete_agent_space(agentSpaceId=space_id), "ResourceNotFoundException"))

    asset_id = client.create_asset(
        agentSpaceId=space_id, assetType="artifact",
        metadata={"title": "probe asset", "description": "the positive control"},
        content={"file": {"path": "a.txt", "body": {"text": "content"}}},
    )["asset"]["assetId"]
    ctx.on_cleanup(_teardown(lambda: client.delete_asset(agentSpaceId=space_id, assetId=asset_id),
                             "ResourceNotFoundException"))

    control = client.get_asset(agentSpaceId=space_id, assetId=asset_id)
    assert control["asset"]["assetId"] == asset_id, f"positive control failed: {control!r}"

    missing_asset_id = ctx.unique_name("sim2real-behav-devops-agent-missing-asset-")
    code, message = _error(lambda: client.get_asset(agentSpaceId=space_id, assetId=missing_asset_id))
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code}: {message!r}"
    assert message == f"Asset not found: {missing_asset_id}", f"unexpected message {message!r}"

    missing_space_id = ctx.unique_name("sim2real-behav-devops-agent-missing-space-")
    code, message = _error(lambda: client.get_asset(agentSpaceId=missing_space_id, assetId=missing_asset_id))
    assert code == "AccessDeniedException", f"expected AccessDeniedException, got {code}: {message!r}"
    assert message == "Access denied", f"unexpected message {message!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
