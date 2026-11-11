"""certificate-hash-order-independent."""
from __future__ import annotations

import io
import time
import uuid
import zipfile
from datetime import datetime, timezone

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "certificate-hash-order-independent"
GROUP = "read-semantics"
SERVICES = ["signer"]


@tags("axis:happy-path", "cap:c2", "cap:c4", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """For a revoked signing job, GetRevocationStatus with the same two certificate hashes in either order
    reports the jobArn as revoked both times, with identical revokedEntities.
    """
    signer = ctx.client("signer")
    s3 = ctx.client("s3")

    profile_name = ctx.unique_name("sim2real_signer_hashord_").replace("-", "_")
    put_resp = signer.put_signing_profile(profileName=profile_name, platformId="AWSLambda-SHA384-ECDSA")
    profile_version_arn = put_resp["profileVersionArn"]
    ctx.on_cleanup(lambda: _safe_cancel(signer, profile_name))

    src_bucket, dst_bucket = _provision_buckets(ctx, s3)
    job_arn = _start_and_wait_job(ctx, signer, s3, src_bucket, dst_bucket, profile_name, "hashorder.zip")

    signer.revoke_signature(jobId=job_arn.rsplit("/", 1)[-1], reason="behavioral-check-hash-order")

    hash_one, hash_two = "d" * 192, "e" * 192
    common = dict(
        platformId="Notation-OCI-SHA384-ECDSA",
        jobArn=job_arn,
        profileVersionArn=profile_version_arn,
        signatureTimestamp=datetime.now(timezone.utc),
    )

    forward = _poll_until_job_revoked(signer, job_arn, common, [hash_one, hash_two])
    assert forward is not None, "job never appeared in revokedEntities after revoke_signature"
    assert job_arn in forward

    reverse = signer.get_revocation_status(certificateHashes=[hash_two, hash_one], **common)["revokedEntities"]
    assert job_arn in reverse, f"reversing certificateHashes order lost the revocation: {reverse}"
    assert forward == reverse, f"certificateHashes order changed revokedEntities: forward={forward} reverse={reverse}"


def _safe_cancel(signer, profile_name: str) -> None:
    try:
        signer.cancel_signing_profile(profileName=profile_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _minimal_zip_bytes() -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("hello.txt", b"sim2real signer behavioral check payload")
    return buf.getvalue()


def _provision_buckets(ctx, s3):
    src_bucket = ctx.unique_name("sim2real-signer-hosrc-").replace("_", "-").lower()
    dst_bucket = ctx.unique_name("sim2real-signer-hodst-").replace("_", "-").lower()
    kwargs = {}
    if ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(Bucket=src_bucket, **kwargs)
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(s3, src_bucket, versioned=True))
    s3.create_bucket(Bucket=dst_bucket, **kwargs)
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(s3, dst_bucket, versioned=False))
    s3.put_bucket_versioning(Bucket=src_bucket, VersioningConfiguration={"Status": "Enabled"})
    return src_bucket, dst_bucket


def _empty_and_delete_bucket(s3, bucket: str, versioned: bool) -> None:
    try:
        if versioned:
            paginator = s3.get_paginator("list_object_versions")
            for page in paginator.paginate(Bucket=bucket):
                objs = [{"Key": v["Key"], "VersionId": v["VersionId"]} for v in page.get("Versions", [])]
                objs += [
                    {"Key": m["Key"], "VersionId": m["VersionId"]}
                    for m in page.get("DeleteMarkers", [])
                ]
                if objs:
                    failed = s3.delete_objects(Bucket=bucket, Delete={"Objects": objs}).get("Errors")
                    if failed:
                        raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
        else:
            paginator = s3.get_paginator("list_objects_v2")
            for page in paginator.paginate(Bucket=bucket):
                objs = [{"Key": o["Key"]} for o in page.get("Contents", [])]
                if objs:
                    failed = s3.delete_objects(Bucket=bucket, Delete={"Objects": objs}).get("Errors")
                    if failed:
                        raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
        s3.delete_bucket(Bucket=bucket)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchBucket":
            raise


def _poll_job_status(signer, job_id: str, timeout_s: float = 120.0, interval_s: float = 5.0):
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        job = signer.describe_signing_job(jobId=job_id)
        if job["status"] in ("Succeeded", "Failed"):
            return job
        time.sleep(interval_s)
    return None


def _start_and_wait_job(ctx, signer, s3, src_bucket, dst_bucket, profile_name, key) -> str:
    version_id = s3.put_object(Bucket=src_bucket, Key=key, Body=_minimal_zip_bytes())["VersionId"]
    start_resp = signer.start_signing_job(
        source={"s3": {"bucketName": src_bucket, "key": key, "version": version_id}},
        destination={"s3": {"bucketName": dst_bucket}},
        profileName=profile_name,
        clientRequestToken=str(uuid.uuid4()),
    )
    job_id = start_resp["jobId"]
    job_owner = start_resp["jobOwner"]
    job = _poll_job_status(signer, job_id)
    assert job is not None, f"signing job {job_id} never reached a terminal status"
    assert job["status"] == "Succeeded", f"signing job {job_id} failed: {job.get('statusReason')}"
    return f"arn:aws:signer:{ctx.region}:{job_owner}:/signing-jobs/{job_id}"


def _poll_until_job_revoked(
    signer, job_arn: str, common: dict, certificate_hashes: list, timeout_s: float = 60.0, interval_s: float = 3.0
):
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        resp = signer.get_revocation_status(certificateHashes=certificate_hashes, **common)
        if job_arn in resp["revokedEntities"]:
            return resp["revokedEntities"]
        time.sleep(interval_s)
    return None


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
