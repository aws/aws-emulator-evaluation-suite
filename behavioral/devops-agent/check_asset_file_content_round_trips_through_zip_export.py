"""asset-file-content-round-trips-through-zip-export."""
from __future__ import annotations

import io
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "asset-file-content-round-trips-through-zip-export"
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


@tags("axis:happy-path", "cap:c1", "concern:data-plane", "plane:data", "dp:api")
def run(ctx) -> None:
    """GetAssetFile returns the exact bytes an asset's file was created with, and
    GetAssetContent's zip export packages that same file unmodified.
    """
    client = ctx.client("devops-agent")
    space_name = ctx.unique_name("sim2real-behav-devops-agent-space-")
    space_id = client.create_agent_space(name=space_name, tags={"sim2real": "probe"})["agentSpace"]["agentSpaceId"]
    ctx.on_cleanup(_teardown(lambda: client.delete_agent_space(agentSpaceId=space_id), "ResourceNotFoundException"))

    body_text = '{"probe": "sim2real-behav-devops-agent-content", "n": 42}'
    asset_id = client.create_asset(
        agentSpaceId=space_id, assetType="artifact",
        metadata={"title": "probe artifact", "description": "content round-trip"},
        content={"file": {"path": "data.json", "body": {"text": body_text}}},
    )["asset"]["assetId"]
    ctx.on_cleanup(_teardown(lambda: client.delete_asset(agentSpaceId=space_id, assetId=asset_id),
                             "ResourceNotFoundException"))

    file_resp = client.get_asset_file(agentSpaceId=space_id, assetId=asset_id, path="data.json")
    assert file_resp["file"]["content"]["text"] == body_text, (
        f"GetAssetFile returned {file_resp['file']['content']!r}, expected the created text"
    )

    content_resp = client.get_asset_content(agentSpaceId=space_id, assetId=asset_id)
    zip_bytes = content_resp["content"]["zipFile"]
    archive = zipfile.ZipFile(io.BytesIO(zip_bytes))
    names = archive.namelist()
    assert names == ["data.json"], f"zip export contains {names!r}, expected exactly ['data.json']"
    extracted = archive.read("data.json").decode("utf-8")
    assert extracted == body_text, f"zip entry content is {extracted!r}, expected the created text"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
