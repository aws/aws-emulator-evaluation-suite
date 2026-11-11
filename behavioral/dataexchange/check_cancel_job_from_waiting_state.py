"""cancel-job-from-waiting-state."""
from __future__ import annotations

import base64
import hashlib

from behavioral_harness import tags

CHECK = "cancel-job-from-waiting-state"
GROUP = "state-transitions"
SERVICES = ["dataexchange"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CancelJob on a WAITING job (never started) transitions it straight to CANCELLED."""
    dx = ctx.client("dataexchange")
    dataset_id = _create_dataset(ctx, dx)
    revision_id = _create_revision(ctx, dx, dataset_id)

    md5_b64 = base64.b64encode(hashlib.md5(b"sim2real-unused-body").digest()).decode()
    job = dx.create_job(
        Type="IMPORT_ASSET_FROM_SIGNED_URL",
        Details={
            "ImportAssetFromSignedUrl": {
                "AssetName": "sim2real-never-uploaded.txt",
                "DataSetId": dataset_id,
                "Md5Hash": md5_b64,
                "RevisionId": revision_id,
            }
        },
    )
    job_id = job["Id"]
    assert job["State"] == "WAITING", f"expected freshly created job to be WAITING, got {job['State']}"

    dx.cancel_job(JobId=job_id)

    cancelled = dx.get_job(JobId=job_id)
    assert cancelled["State"] == "CANCELLED", (
        f"expected CancelJob on a WAITING job to leave it CANCELLED, got {cancelled['State']}"
    )


def _create_dataset(ctx, dx) -> str:
    name = ctx.unique_name("sim2real-dx-ds-")
    ds = dx.create_data_set(
        AssetType="S3_SNAPSHOT",
        Description="sim2real check",
        Name=name,
        Tags={"sim2real-owner": "behavioral-check", "sim2real-check": CHECK},
    )
    ctx.on_cleanup(lambda: dx.delete_data_set(DataSetId=ds["Id"]))
    return ds["Id"]


def _create_revision(ctx, dx, dataset_id: str) -> str:
    rev = dx.create_revision(
        DataSetId=dataset_id,
        Comment="sim2real revision",
        Tags={"sim2real-owner": "behavioral-check", "sim2real-check": CHECK},
    )
    ctx.on_cleanup(lambda: dx.delete_revision(DataSetId=dataset_id, RevisionId=rev["Id"]))
    return rev["Id"]


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
