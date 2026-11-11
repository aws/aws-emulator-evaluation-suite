"""concurrent-start-job-race-single-winner."""
from __future__ import annotations

import base64
import hashlib
from concurrent.futures import ThreadPoolExecutor

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "concurrent-start-job-race-single-winner"
GROUP = "concurrency"
SERVICES = ["dataexchange"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """StartJob's WAITING->IN_PROGRESS transition is atomic: firing N concurrent
    StartJob calls at the same WAITING job must let exactly one succeed, with every
    other racer rejected with ConflictException, never two winners."""
    dx = ctx.client("dataexchange")
    dataset_id = _create_dataset(ctx, dx)
    revision_id = _create_revision(ctx, dx, dataset_id)

    md5_b64 = base64.b64encode(hashlib.md5(b"sim2real-race-body").digest()).decode()
    job = dx.create_job(
        Type="IMPORT_ASSET_FROM_SIGNED_URL",
        Details={
            "ImportAssetFromSignedUrl": {
                "AssetName": "sim2real-race.txt",
                "DataSetId": dataset_id,
                "Md5Hash": md5_b64,
                "RevisionId": revision_id,
            }
        },
    )
    job_id = job["Id"]
    assert job["State"] == "WAITING", f"expected new job {job_id} to start WAITING, got {job['State']}"

    racer_count = 8

    def _racer(_: int):
        try:
            dx.start_job(JobId=job_id)
            return "OK", None
        except ClientError as e:
            return e.response["Error"]["Code"], e.response["Error"].get("Message", "")

    with ThreadPoolExecutor(max_workers=racer_count) as pool:
        outcomes = list(pool.map(_racer, range(racer_count)))

    winners = [o for o in outcomes if o[0] == "OK"]
    losers = [o for o in outcomes if o[0] != "OK"]
    assert len(winners) == 1, f"expected exactly one StartJob winner, got {len(winners)}: {outcomes}"
    assert len(losers) == racer_count - 1, f"expected {racer_count - 1} losing racers, got {len(losers)}: {outcomes}"
    assert all(code == "ConflictException" for code, _message in losers), losers
    expected = "Cannot start the requested Job. To start a Job, it must be in the WAITING state."
    assert all(message == expected for _code, message in losers), losers

    final_state = dx.get_job(JobId=job_id)["State"]
    assert final_state != "WAITING", f"expected job {job_id} to move off WAITING once the winner started it, still {final_state}"


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
