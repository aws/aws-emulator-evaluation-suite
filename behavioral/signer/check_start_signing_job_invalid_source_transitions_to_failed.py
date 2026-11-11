"""start-signing-job-invalid-source-transitions-to-failed."""
from __future__ import annotations

import io
import time
import zipfile

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "start-signing-job-invalid-source-transitions-to-failed"
GROUP = "state"
SERVICES = ["signer"]

LAMBDA_PLATFORM = "AWSLambda-SHA384-ECDSA"


@tags("axis:happy-path", "cap:c4", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """StartSigningJob on a valid zip reaches Succeeded with a signed object at the destination, while the same
    job on a non-zip source reaches Failed with a statusReason and leaves no signed object.
    """
    signer = ctx.client("signer")
    s3 = ctx.client("s3")

    name = _profile_name(ctx, "startfail")
    ctx.on_cleanup(lambda: _cancel_quietly(signer, name))
    signer.put_signing_profile(profileName=name, platformId=LAMBDA_PLATFORM, tags={"sim2real": CHECK})

    src_bucket = ctx.unique_name("sim2real-signer-src-")
    dst_bucket = ctx.unique_name("sim2real-signer-dst-")
    _create_bucket(s3, ctx, src_bucket)
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(s3, src_bucket))
    _create_bucket(s3, ctx, dst_bucket)
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(s3, dst_bucket))
    s3.put_bucket_tagging(Bucket=src_bucket, Tagging={"TagSet": [{"Key": "sim2real", "Value": CHECK}]})
    s3.put_bucket_tagging(Bucket=dst_bucket, Tagging={"TagSet": [{"Key": "sim2real", "Value": CHECK}]})
    s3.put_bucket_versioning(Bucket=src_bucket, VersioningConfiguration={"Status": "Enabled"})
    destination = {"s3": {"bucketName": dst_bucket, "prefix": "signed/"}}

    def _sign(body: bytes):
        key = "code.zip"
        version_id = s3.put_object(Bucket=src_bucket, Key=key, Body=body)["VersionId"]
        job_id = signer.start_signing_job(
            source={"s3": {"bucketName": src_bucket, "key": key, "version": version_id}},
            destination=destination,
            profileName=name,
            clientRequestToken=ctx.unique_name("sim2real-token-"),
        )["jobId"]

        def probe():
            return signer.describe_signing_job(jobId=job_id)

        job = _poll_until(probe, lambda j: j["status"] != "InProgress", timeout_s=300.0, interval_s=10.0)
        return job_id, job

    # ---- positive control: a genuinely valid zip through the IDENTICAL profile, buckets and
    # destination prefix must reach Succeeded and produce a real signed object at the
    # destination, proving the wiring can complete a job before we ever ask it to reject one ----
    good_job_id, good_job = _sign(_valid_zip())
    assert good_job["status"] == "Succeeded", (
        f"a valid zip source ({good_job_id!r}) did not sign successfully through profile "
        f"{name!r}: status={good_job['status']!r} reason={good_job.get('statusReason')!r}"
    )
    signed = good_job.get("signedObject", {}).get("s3", {})
    assert signed.get("bucketName") == dst_bucket, (
        f"expected the signed object for {good_job_id!r} in bucket {dst_bucket!r}, "
        f"DescribeSigningJob reported signedObject={signed!r}"
    )
    s3.head_object(Bucket=dst_bucket, Key=signed["key"])  # independent read, at the destination

    # ---- break exactly one thing: the source bytes are not a valid zip archive ----
    bad_job_id, bad_job = _sign(b"this is not a valid zip archive")
    assert bad_job["status"] == "Failed", (
        f"a non-zip source ({bad_job_id!r}) did not transition to Failed: "
        f"status={bad_job['status']!r} reason={bad_job.get('statusReason')!r}"
    )
    assert bad_job.get("statusReason"), (
        f"a Failed signing job {bad_job_id!r} reported no statusReason"
    )

    # ---- effect absent: no signed object exists for the failed job, at the destination ----
    assert not bad_job.get("signedObject", {}).get("s3"), (
        f"a Failed signing job {bad_job_id!r} reported a signedObject: {bad_job['signedObject']!r}"
    )
    listing = s3.list_objects_v2(Bucket=dst_bucket, Prefix="signed/")
    leaked = [o["Key"] for o in listing.get("Contents", []) if bad_job_id in o["Key"]]
    assert not leaked, (
        f"expected no object written under signed/ for the failed job {bad_job_id!r}, found {leaked!r}"
    )


def _valid_zip() -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("index.py", "def handler(event, context): return 'ok'\n")
    return buf.getvalue()


def _profile_name(ctx, kind: str) -> str:
    return ctx.unique_name(f"sim2real-signer-{kind}-").replace("-", "_")


def _cancel_quietly(signer, profile_name: str) -> None:
    from botocore.exceptions import ClientError

    try:
        signer.cancel_signing_profile(profileName=profile_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _create_bucket(s3, ctx, bucket: str) -> None:
    kwargs = {"Bucket": bucket}
    if ctx.region != "us-east-1":  # S3 quirk: us-east-1 rejects an explicit LocationConstraint
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kwargs)


def _empty_and_delete_bucket(s3, bucket: str) -> None:
    from botocore.exceptions import ClientError

    try:
        paginator = s3.get_paginator("list_object_versions")
        for page in paginator.paginate(Bucket=bucket):
            objects = [
                {"Key": v["Key"], "VersionId": v["VersionId"]} for v in page.get("Versions", [])
            ]
            objects += [
                {"Key": d["Key"], "VersionId": d["VersionId"]}
                for d in page.get("DeleteMarkers", [])
            ]
            if objects:
                failed = s3.delete_objects(Bucket=bucket, Delete={"Objects": objects}).get("Errors")
                if failed:
                    raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
        s3.delete_bucket(Bucket=bucket)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchBucket":
            raise


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last value: {last!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
