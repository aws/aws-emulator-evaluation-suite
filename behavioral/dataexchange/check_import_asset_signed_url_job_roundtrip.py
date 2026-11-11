"""import-asset-signed-url-job-roundtrip."""
from __future__ import annotations

import base64
import hashlib
import time
import urllib.request

from behavioral_harness import tags

CHECK = "import-asset-signed-url-job-roundtrip"
GROUP = "data-plane"
SERVICES = ["dataexchange"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:data-plane", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """A signed-URL import job starts WAITING, accepts a PUT of the bytes, and reaches COMPLETED with exactly one
    S3_SNAPSHOT asset whose Size equals the uploaded byte count."""
    dx = ctx.client("dataexchange")
    dataset_id = _create_dataset(ctx, dx)
    revision_id = _create_revision(ctx, dx, dataset_id)

    content = b"sim2real-data-exchange-native-roundtrip-payload-0123456789"
    asset_name = "sim2real-roundtrip-asset.bin"
    md5_b64 = base64.b64encode(hashlib.md5(content).digest()).decode()

    job = dx.create_job(
        Type="IMPORT_ASSET_FROM_SIGNED_URL",
        Details={
            "ImportAssetFromSignedUrl": {
                "AssetName": asset_name,
                "DataSetId": dataset_id,
                "Md5Hash": md5_b64,
                "RevisionId": revision_id,
            }
        },
    )
    job_id = job["Id"]
    assert job["State"] == "WAITING", f"expected a fresh import job to start WAITING, got {job['State']}"
    signed_url = job["Details"]["ImportAssetFromSignedUrl"]["SignedUrl"]

    # The signed URL expires one minute after CreateJob, so upload right away.
    target_url, route_headers = ctx.endpoint_route(signed_url)
    req = urllib.request.Request(
        target_url, data=content, method="PUT", headers={"Content-MD5": md5_b64, **route_headers}
    )
    with urllib.request.urlopen(req, timeout=30) as resp:
        assert resp.status in (200, 201), f"signed URL PUT failed: HTTP {resp.status}"

    dx.start_job(JobId=job_id)
    started = dx.get_job(JobId=job_id)
    assert started["State"] in ("IN_PROGRESS", "COMPLETED"), (
        f"expected StartJob to move the job off WAITING, still {started['State']}"
    )

    final_state = _poll_job_state(dx, job_id, {"COMPLETED", "ERROR", "TIMED_OUT"}, timeout_s=120)
    final = dx.get_job(JobId=job_id)
    assert final_state == "COMPLETED", f"import job ended in {final_state}: {final.get('Errors')}"

    assets = dx.list_revision_assets(DataSetId=dataset_id, RevisionId=revision_id)["Assets"]
    matches = [a for a in assets if a["Name"] == asset_name]
    assert len(matches) == 1, f"expected exactly 1 asset named {asset_name!r}, found {len(matches)}"
    asset_id = matches[0]["Id"]

    asset = dx.get_asset(AssetId=asset_id, DataSetId=dataset_id, RevisionId=revision_id)
    assert asset["AssetType"] == "S3_SNAPSHOT", f"expected asset type S3_SNAPSHOT, got {asset['AssetType']}"
    reported_size = asset["AssetDetails"]["S3SnapshotAsset"]["Size"]
    assert reported_size == len(content), f"expected asset size {len(content)}, got {reported_size}"


def _create_dataset(ctx, dx) -> str:
    name = ctx.unique_name("sim2real-dx-ds-")
    ds = dx.create_data_set(
        AssetType="S3_SNAPSHOT",
        Description="sim2real check",
        Name=name,
        Tags={"sim2real-owner": "behavioral-check"},
    )
    ctx.on_cleanup(lambda: dx.delete_data_set(DataSetId=ds["Id"]))
    return ds["Id"]


def _create_revision(ctx, dx, dataset_id: str) -> str:
    rev = dx.create_revision(
        DataSetId=dataset_id,
        Comment="sim2real revision",
        Tags={"sim2real-owner": "behavioral-check"},
    )
    ctx.on_cleanup(lambda: dx.delete_revision(DataSetId=dataset_id, RevisionId=rev["Id"]))
    return rev["Id"]


def _poll_job_state(dx, job_id: str, target_states: set, timeout_s: float = 120.0, interval_s: float = 2.0) -> str:
    deadline = time.monotonic() + timeout_s
    state = dx.get_job(JobId=job_id)["State"]
    while state not in target_states and time.monotonic() < deadline:
        time.sleep(interval_s)
        state = dx.get_job(JobId=job_id)["State"]
    return state


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
