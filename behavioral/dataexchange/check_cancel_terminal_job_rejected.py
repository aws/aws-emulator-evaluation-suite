"""cancel-terminal-job-rejected."""
from __future__ import annotations

import base64
import hashlib

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cancel-terminal-job-rejected"
GROUP = "overly-permissive"
SERVICES = ["dataexchange"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CancelJob only works while a job is WAITING or IN_PROGRESS. The first cancel
    (positive control) takes a WAITING job to CANCELLED; cancelling that same job again
    is rejected and the job stays CANCELLED (no state is lost or changed)."""
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

    dx.cancel_job(JobId=job_id)
    cancelled = dx.get_job(JobId=job_id)
    assert cancelled["State"] == "CANCELLED", f"expected CANCELLED after first cancel, got {cancelled['State']!r}"

    code, message = _error(lambda: dx.cancel_job(JobId=job_id))
    assert code == "ConflictException", f"expected ConflictException cancelling an already-CANCELLED job, got {code!r}"
    assert message == "Cannot cancel the requested Job. To cancel a Job, it must be in the WAITING state.", f"expected the exact refusal message, got {message!r}"

    still_cancelled = dx.get_job(JobId=job_id)
    assert still_cancelled["State"] == "CANCELLED", (
        f"rejected re-cancel must leave state unchanged; expected CANCELLED, got {still_cancelled['State']!r}"
    )


def _error(fn):
    """Call fn(); return its botocore error code and message. An unexpected SUCCESS raises,
    because an emulator ACCEPTING a call real AWS refuses must not read as a code mismatch."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


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


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
