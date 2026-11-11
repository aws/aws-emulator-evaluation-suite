"""revision-asset-finalize-state-transition."""
from __future__ import annotations

import base64
import hashlib
import time
import urllib.request

from behavioral_harness import tags

CHECK = "revision-asset-finalize-state-transition"
GROUP = "state-transitions"
SERVICES = ["dataexchange"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:data-plane", "concern:representation", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """A revision with >=1 completed asset can be finalized; Finalized flips false->true
    and is visible via both GetRevision and ListDataSetRevisions."""
    dx = ctx.client("dataexchange")
    dataset_id = _create_dataset(ctx, dx)
    revision_id = _create_revision(ctx, dx, dataset_id)

    revision = dx.get_revision(DataSetId=dataset_id, RevisionId=revision_id)
    assert revision["Finalized"] is False, f"expected a fresh revision to be unfinalized, got {revision['Finalized']}"

    _import_asset_via_signed_url(
        ctx, dx, dataset_id, revision_id, b"sim2real-payload-bytes", "sim2real-asset.txt"
    )

    dx.update_revision(DataSetId=dataset_id, RevisionId=revision_id, Finalized=True)

    revision = dx.get_revision(DataSetId=dataset_id, RevisionId=revision_id)
    assert revision["Finalized"] is True, f"expected Finalized=True after UpdateRevision, got {revision['Finalized']}"

    listed = dx.list_data_set_revisions(DataSetId=dataset_id)["Revisions"]
    matches = [r for r in listed if r["Id"] == revision_id]
    assert len(matches) == 1, f"expected exactly 1 revision with id {revision_id} in ListDataSetRevisions, got {len(matches)}"
    assert matches[0]["Finalized"] is True, f"expected ListDataSetRevisions to reflect Finalized=True, got {matches[0]['Finalized']}"


def _create_dataset(ctx, dx) -> str:
    name = ctx.unique_name("sim2real-dx-ds-")
    ds = dx.create_data_set(
        AssetType="S3_SNAPSHOT",
        Description="sim2real check",
        Name=name,
        Tags={"sim2real-check": CHECK},
    )
    ctx.on_cleanup(lambda: dx.delete_data_set(DataSetId=ds["Id"]))
    return ds["Id"]


def _create_revision(ctx, dx, dataset_id: str) -> str:
    rev = dx.create_revision(
        DataSetId=dataset_id, Comment="sim2real revision", Tags={"sim2real-check": CHECK}
    )
    ctx.on_cleanup(lambda: dx.delete_revision(DataSetId=dataset_id, RevisionId=rev["Id"]))
    return rev["Id"]


def _import_asset_via_signed_url(ctx, dx, dataset_id, revision_id, content: bytes, asset_name: str) -> str:
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
    signed_url, route = ctx.endpoint_route(job["Details"]["ImportAssetFromSignedUrl"]["SignedUrl"])
    # The signed URL is only valid for one minute after CreateJob, so upload immediately.
    req = urllib.request.Request(
        signed_url, data=content, method="PUT", headers={"Content-MD5": md5_b64, **route}
    )
    with urllib.request.urlopen(req, timeout=30) as resp:
        if resp.status not in (200, 201):
            raise AssertionError(f"signed URL upload failed: HTTP {resp.status}")
    dx.start_job(JobId=job_id)
    _poll_job_state(ctx, dx, job_id, {"COMPLETED", "ERROR", "TIMED_OUT"}, timeout_s=90)
    final = dx.get_job(JobId=job_id)
    assert final["State"] == "COMPLETED", f"import job ended in {final['State']}: {final.get('Errors')}"
    return job_id


def _poll_job_state(ctx, dx, job_id: str, target_states: set, timeout_s: float = 90.0, interval_s: float = 2.0) -> str:
    deadline = time.monotonic() + timeout_s
    state = dx.get_job(JobId=job_id)["State"]
    while state not in target_states and time.monotonic() < deadline:
        time.sleep(interval_s)
        state = dx.get_job(JobId=job_id)["State"]
    return state


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
