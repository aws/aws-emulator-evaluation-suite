"""start-signing-job-client-request-token-idempotent."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "start-signing-job-client-request-token-idempotent"
GROUP = "data-plane"
SERVICES = ["signer"]

LAMBDA_PLATFORM = "AWSLambda-SHA384-ECDSA"


@tags("axis:happy-path", "cap:c1", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """StartSigningJob twice with the same clientRequestToken returns one jobId and ListSigningJobs for the
    profile shows exactly that job, while a fresh token mints a distinct second job listed alongside it.
    """
    signer = ctx.client("signer")
    s3 = ctx.client("s3")
    account_id = ctx.client("sts").get_caller_identity()["Account"]

    name = _profile_name(ctx, "idempotent")
    ctx.on_cleanup(lambda: _cancel_quietly(signer, name))
    signer.put_signing_profile(profileName=name, platformId=LAMBDA_PLATFORM)

    src_bucket = ctx.unique_name("sim2real-signer-src-")
    dst_bucket = ctx.unique_name("sim2real-signer-dst-")
    _create_bucket(s3, ctx, src_bucket)
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(s3, src_bucket))
    _create_bucket(s3, ctx, dst_bucket)
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(s3, dst_bucket))
    s3.put_bucket_versioning(Bucket=src_bucket, VersioningConfiguration={"Status": "Enabled"})

    key = "unsigned-code.zip"
    version_id = s3.put_object(Bucket=src_bucket, Key=key, Body=b"idempotency-test-body")[
        "VersionId"
    ]

    token = ctx.unique_name("sim2real-token-")
    source = {"s3": {"bucketName": src_bucket, "key": key, "version": version_id}}
    destination = {"s3": {"bucketName": dst_bucket, "prefix": "signed/"}}

    first_job_id = signer.start_signing_job(
        source=source, destination=destination, profileName=name, clientRequestToken=token
    )["jobId"]
    second_job_id = signer.start_signing_job(
        source=source, destination=destination, profileName=name, clientRequestToken=token
    )["jobId"]
    assert first_job_id == second_job_id, (
        f"replaying the same clientRequestToken must return the original jobId, "
        f"got {first_job_id!r} then {second_job_id!r}"
    )

    # Independent read #1: DescribeSigningJob (not the StartSigningJob response) confirms
    # first_job_id names a real job on this profile and source.
    job = signer.describe_signing_job(jobId=first_job_id)
    assert job["profileName"] == name, job
    assert job["source"]["s3"]["bucketName"] == src_bucket, job
    assert job["source"]["s3"]["key"] == key, job

    # Independent read #2: ListSigningJobs, counted for THIS run's own profile, proves the
    # duplicated token produced exactly one job record -- not two jobs that happen to echo the
    # same id back in their StartSigningJob response bodies.
    jobs_for_profile = _poll_until(
        lambda: _list_jobs_for_profile(signer, account_id, name),
        lambda jobs: len(jobs) >= 1,
        timeout_s=60.0,
        interval_s=5.0,
    )
    job_ids = sorted(j["jobId"] for j in jobs_for_profile)
    assert job_ids == [first_job_id], (
        f"expected exactly the one deduped job {first_job_id!r} for profile {name!r}, "
        f"ListSigningJobs shows {job_ids!r}"
    )

    # Positive control: a FRESH clientRequestToken on an otherwise identical call is not
    # swallowed by whatever cached the first id -- it mints a genuinely distinct second job,
    # independently visible alongside the first.
    other_token = ctx.unique_name("sim2real-token-")
    third_job_id = signer.start_signing_job(
        source=source, destination=destination, profileName=name, clientRequestToken=other_token
    )["jobId"]
    assert third_job_id != first_job_id, "a fresh clientRequestToken must not dedupe to the earlier job"

    jobs_after_control = _poll_until(
        lambda: _list_jobs_for_profile(signer, account_id, name),
        lambda jobs: len(jobs) >= 2,
        timeout_s=60.0,
        interval_s=5.0,
    )
    job_ids_after_control = sorted(j["jobId"] for j in jobs_after_control)
    assert job_ids_after_control == sorted([first_job_id, third_job_id]), (
        f"expected exactly the deduped job and the fresh-token job, got {job_ids_after_control!r}"
    )


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
    if ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kwargs)


def _list_jobs_for_profile(signer, account_id: str, profile_name: str) -> list[dict]:
    jobs = []
    next_token = None
    for _ in range(20):
        kwargs = {"jobInvoker": account_id, "maxResults": 25}
        if next_token:
            kwargs["nextToken"] = next_token
        resp = signer.list_signing_jobs(**kwargs)
        jobs.extend(j for j in resp.get("jobs", []) if j.get("profileName") == profile_name)
        next_token = resp.get("nextToken")
        if not next_token:
            break
    return jobs


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last value: {last!r}")


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


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
