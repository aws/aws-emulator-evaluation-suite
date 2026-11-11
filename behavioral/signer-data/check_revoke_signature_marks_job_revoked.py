"""revoke-signature-marks-job-revoked."""
from __future__ import annotations

import io
import time
import uuid
import zipfile
from datetime import datetime, timezone

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "revoke-signature-marks-job-revoked"
GROUP = "state"
SERVICES = ["signer-data"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """RevokeSignature on a never-created job fails with ResourceNotFoundException and the exact message and
    leaves the real job unrevoked; revoking the real job puts its jobArn in GetRevocationStatus
    revokedEntities while the unrevoked profileVersionArn stays out.
    """
    signer = ctx.client("signer")
    s3 = ctx.client("s3")

    profile_name = ctx.unique_name("sim2real-signer-rvkjob-").replace("-", "_")
    put_resp = signer.put_signing_profile(profileName=profile_name, platformId="AWSLambda-SHA384-ECDSA")
    profile_version_arn = put_resp["profileVersionArn"]
    ctx.on_cleanup(lambda: _safe_cancel(signer, profile_name))

    src_bucket, dst_bucket = _provision_buckets(ctx, s3)
    key = "code.zip"
    version_id = s3.put_object(Bucket=src_bucket, Key=key, Body=_minimal_zip_bytes())["VersionId"]

    start_resp = signer.start_signing_job(
        source={"s3": {"bucketName": src_bucket, "key": key, "version": version_id}},
        destination={"s3": {"bucketName": dst_bucket}},
        profileName=profile_name,
        clientRequestToken=str(uuid.uuid4()),
    )
    job_id = start_resp["jobId"]
    job_owner = start_resp["jobOwner"]
    job_arn = f"arn:aws:signer:{ctx.region}:{job_owner}:/signing-jobs/{job_id}"

    job = _poll_job_status(signer, job_id, timeout_s=120.0)
    assert job is not None, "signing job never reached a terminal status"
    assert job["status"] == "Succeeded", f"signing job failed: {job.get('statusReason')}"

    # Negative sub-test (documented, exact code): revoking a job that never existed
    # is rejected, and the real job is unaffected by the failed attempt.
    missing_job_id = str(uuid.uuid4())
    code, message = _client_error(
        lambda: signer.revoke_signature(jobId=missing_job_id, reason="probe-nonexistent-job")
    )
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code!r}"
    expected = f"Signing Job with id {missing_job_id} does not exist."
    assert message == expected, f"expected message {expected!r}, got {message!r}"
    unaffected = signer.describe_signing_job(jobId=job_id)
    assert "revocationRecord" not in unaffected, (
        f"real job {job_id} gained a revocationRecord after an unrelated revoke attempt failed: "
        f"{unaffected.get('revocationRecord')!r}"
    )

    signer.revoke_signature(jobId=job_id, reason="behavioral-check-revoke-signature")

    revoked_job = _poll_until_has_revocation_record(signer, job_id, timeout_s=60.0)
    assert revoked_job is not None, "signing job never gained a revocationRecord"

    common = dict(
        platformId="Notation-OCI-SHA384-ECDSA",
        jobArn=job_arn,
        profileVersionArn=profile_version_arn,
        certificateHashes=["a" * 192],
        signatureTimestamp=datetime.now(timezone.utc),
    )
    revoked_entities = _poll_until_job_revoked(signer, job_arn, common, timeout_s=60.0)
    assert revoked_entities is not None, "jobArn never appeared in revokedEntities"
    assert job_arn in revoked_entities, f"expected {job_arn!r} in revokedEntities, got {revoked_entities!r}"
    assert profile_version_arn not in revoked_entities, (
        f"unrelated profileVersionArn {profile_version_arn!r} was revoked too; "
        f"revokedEntities={revoked_entities!r}"
    )


def _client_error(fn):
    """Call fn(); return its botocore Error code and message. An unexpected SUCCESS raises, because
    an emulator ACCEPTING a call real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


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
    src_bucket = ctx.unique_name("sim2real-signer-src-").replace("_", "-").lower()
    dst_bucket = ctx.unique_name("sim2real-signer-dst-").replace("_", "-").lower()
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


def _poll_job_status(signer, job_id: str, timeout_s: float, interval_s: float = 5.0):
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        job = signer.describe_signing_job(jobId=job_id)
        if job["status"] in ("Succeeded", "Failed"):
            return job
        time.sleep(interval_s)
    return None


def _poll_until_has_revocation_record(signer, job_id: str, timeout_s: float, interval_s: float = 3.0):
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        job = signer.describe_signing_job(jobId=job_id)
        if "revocationRecord" in job:
            return job
        time.sleep(interval_s)
    return None


def _poll_until_job_revoked(signer, job_arn: str, common: dict, timeout_s: float, interval_s: float = 3.0):
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        resp = signer.get_revocation_status(**common)
        if job_arn in resp["revokedEntities"]:
            return resp["revokedEntities"]
        time.sleep(interval_s)
    return None


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
