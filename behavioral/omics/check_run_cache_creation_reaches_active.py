"""run-cache-creation-reaches-active."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "run-cache-creation-reaches-active"
GROUP = "state"
SERVICES = ["omics"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateRunCache against a real S3 location settles into ACTIVE status."""
    bucket = _create_bucket(ctx)
    omics = ctx.client("omics")

    created = omics.create_run_cache(
        cacheS3Location=f"s3://{bucket}/cache/",
        requestId=ctx.unique_name("sim2real-cachereq-"),
        tags={"sim2real": CHECK},
    )
    cache_id = created["id"]
    ctx.on_cleanup(lambda: omics.delete_run_cache(id=cache_id))

    status = created.get("status")
    deadline = time.monotonic() + 60
    while status not in ("ACTIVE", "FAILED") and time.monotonic() < deadline:
        time.sleep(2)
        status = omics.get_run_cache(id=cache_id)["status"]

    assert status == "ACTIVE", f"run cache {cache_id} ended in status {status!r}"

    described = omics.get_run_cache(id=cache_id)
    assert described["id"] == cache_id
    assert described["cacheS3Uri"].startswith(f"s3://{bucket}/")
    assert described["status"] == "ACTIVE"


def _create_bucket(ctx) -> str:
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-omics-cache-").lower()
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(
            Bucket=bucket,
            CreateBucketConfiguration={"LocationConstraint": ctx.region},
        )
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [{"Key": "sim2real", "Value": CHECK}]})
    ctx.on_cleanup(lambda: s3.delete_bucket(Bucket=bucket))
    return bucket


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
