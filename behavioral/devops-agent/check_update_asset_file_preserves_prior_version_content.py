"""update-asset-file-preserves-prior-version-content."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-asset-file-preserves-prior-version-content"
GROUP = 'asset-lifecycle'
SERVICES = ['devops-agent']


def _teardown(undo, *not_found: str):
    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


@tags("axis:happy-path", "cap:c2", "concern:representation", "concern:data-plane", "plane:data", "dp:api")
def run(ctx) -> None:
    """UpdateAssetFile advances the asset to a new version whose unversioned reads see the
    new content, while the prior version's content stays frozen and separately retrievable.
    """
    client = ctx.client("devops-agent")
    space_name = ctx.unique_name("sim2real-behav-devops-agent-space-")
    space_id = client.create_agent_space(name=space_name, tags={"sim2real": "probe"})["agentSpace"]["agentSpaceId"]
    ctx.on_cleanup(_teardown(lambda: client.delete_agent_space(agentSpaceId=space_id), "ResourceNotFoundException"))

    asset_id = client.create_asset(
        agentSpaceId=space_id, assetType="artifact",
        metadata={"title": "probe artifact", "description": "versioned content"},
        content={"file": {"path": "v.txt", "body": {"text": "hello v1"}}},
    )["asset"]["assetId"]
    ctx.on_cleanup(_teardown(lambda: client.delete_asset(agentSpaceId=space_id, assetId=asset_id),
                             "ResourceNotFoundException"))

    updated = client.update_asset_file(agentSpaceId=space_id, assetId=asset_id, path="v.txt",
                                        content={"text": "hello v2"})
    assert updated["file"]["version"] == 2, f"expected UpdateAssetFile to produce version 2, got {updated['file']!r}"

    latest_file = client.get_asset_file(agentSpaceId=space_id, assetId=asset_id, path="v.txt")
    assert latest_file["file"]["content"]["text"] == "hello v2", (
        f"unversioned read returned {latest_file['file']['content']!r}, expected the new content"
    )

    v1_file = client.get_asset_file(agentSpaceId=space_id, assetId=asset_id, path="v.txt", assetVersion=1)
    assert v1_file["file"]["content"]["text"] == "hello v1", (
        f"version 1 content mutated to {v1_file['file']['content']!r} — old versions must be immutable"
    )

    latest_asset = client.get_asset(agentSpaceId=space_id, assetId=asset_id)
    assert latest_asset["asset"]["version"] == 2, f"GetAsset reports version {latest_asset['asset']['version']!r}"

    versions = {v["version"] for v in client.list_asset_versions(
        agentSpaceId=space_id, assetId=asset_id)["items"]}
    assert versions == {1, 2}, f"ListAssetVersions returned {sorted(versions)!r}, expected {{1, 2}}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
