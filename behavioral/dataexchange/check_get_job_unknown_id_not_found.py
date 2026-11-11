"""get-job-unknown-id-not-found."""
from __future__ import annotations

import base64
import hashlib

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-job-unknown-id-not-found"
GROUP = "error-semantics"
SERVICES = ["dataexchange"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """GetJob on a syntactically valid but never-created JobId returns
    ResourceNotFoundException, while the same call for a real job succeeds."""
    dx = ctx.client("dataexchange")
    dataset_id = _create_dataset(ctx, dx)
    revision_id = _create_revision(ctx, dx, dataset_id)

    md5_b64 = base64.b64encode(hashlib.md5(b"sim2real-unused-body").digest()).decode()
    job = dx.create_job(
        Type="IMPORT_ASSET_FROM_SIGNED_URL",
        Details={
            "ImportAssetFromSignedUrl": {
                "AssetName": "sim2real-lookup.txt",
                "DataSetId": dataset_id,
                "Md5Hash": md5_b64,
                "RevisionId": revision_id,
            }
        },
    )
    real_job_id = job["Id"]

    # Positive control: the real job can be fetched.
    got = dx.get_job(JobId=real_job_id)
    assert got["Id"] == real_job_id, f"expected GetJob to echo {real_job_id!r}, got {got.get('Id')!r}"

    bogus_job_id = "z" * len(real_job_id)
    code, message = _error(lambda: dx.get_job(JobId=bogus_job_id))
    assert code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException for never-created JobId {bogus_job_id!r}, got {code!r}"
    )
    assert message == "The requested resource was not found.", f"expected the exact refusal message, got {message!r}"


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


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
