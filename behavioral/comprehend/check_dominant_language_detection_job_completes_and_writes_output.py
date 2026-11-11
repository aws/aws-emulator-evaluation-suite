"""dominant-language-detection-job-completes-and-writes-output."""
from __future__ import annotations

import io
import json
import tarfile
import time

from behavioral_harness import tags

CHECK = "dominant-language-detection-job-completes-and-writes-output"
GROUP = "lifecycle"
SERVICES = ["comprehend"]


@tags("axis:happy-path", "cap:c4", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """An async dominant-language job moves forward through SUBMITTED, IN_PROGRESS and COMPLETED
    (a poll may miss a transient status) and writes real S3 output."""
    bucket, role_arn = _setup_bucket_and_role(ctx)
    s3 = ctx.client("s3")
    s3.put_object(
        Bucket=bucket,
        Key="input/doc1.txt",
        Body=b"This is a short English document used to exercise the dominant language detection job.",
    )

    comprehend = ctx.client("comprehend")

    def _start_and_poll():
        job_name = ctx.unique_name("sim2real-dlj-").replace("_", "-")

        def _start():
            return comprehend.start_dominant_language_detection_job(
                JobName=job_name,
                InputDataConfig={"S3Uri": f"s3://{bucket}/input/", "InputFormat": "ONE_DOC_PER_FILE"},
                OutputDataConfig={"S3Uri": f"s3://{bucket}/output/"},
                DataAccessRoleArn=role_arn,
            )

        job_id = _retry_role_propagation(_start)["JobId"]
        return (job_id, *_poll_job(ctx, job_id, timeout_s=900))

    # StartDominantLanguageDetectionJob can succeed (the role's trust policy has propagated) while
    # the job itself still fails fast with NO_WRITE_ACCESS_TO_OUTPUT/NO_ACCESS_TO_INPUT — the
    # backend's own permission check runs later, on its own propagation clock, so the initial
    # start-call retry above does not cover it. Retry the whole start+poll cycle with a fresh job
    # only for that specific, known-transient failure signature.
    job_id, seen_statuses, final, fail_message = _retry_on_role_propagation_job_failure(
        _start_and_poll, timeout_s=300.0
    )
    assert final == "COMPLETED", (
        f"job did not complete, statuses observed: {seen_statuses!r}, message: {fail_message!r}"
    )
    lifecycle = ["SUBMITTED", "IN_PROGRESS", "COMPLETED"]
    assert all(status in lifecycle for status in seen_statuses), (
        f"job reported a status outside {lifecycle!r}: {seen_statuses!r}"
    )
    assert seen_statuses == sorted(seen_statuses, key=lifecycle.index), (
        f"job statuses must only move forward through {lifecycle!r}, saw {seen_statuses!r}"
    )

    describe = comprehend.describe_dominant_language_detection_job(JobId=job_id)
    output_uri = describe["DominantLanguageDetectionJobProperties"]["OutputDataConfig"]["S3Uri"]
    assert output_uri.startswith(f"s3://{bucket}/output/"), output_uri

    output_key = _wait_for_s3_object_under_prefix(ctx, bucket, "output/", timeout_s=120)
    assert output_key, f"expected at least one non-empty object written under s3://{bucket}/output/"

    result = _first_json_record_from_output(ctx, bucket, output_key)
    languages = result.get("Languages") or []
    assert languages, f"output record carries no detected languages: {result!r}"
    assert languages[0]["LanguageCode"] == "en", (
        f"expected the English input document to be classified as 'en', got {result!r}"
    )


# ===== helpers =====


def _retry_role_propagation(fn, timeout_s: float = 90.0, interval_s: float = 6.0):
    deadline = time.monotonic() + timeout_s
    last_exc = None
    while time.monotonic() < deadline:
        try:
            return fn()
        except Exception as exc:  # noqa: BLE001 - retry until IAM role propagates
            last_exc = exc
            time.sleep(interval_s)
    raise AssertionError(f"operation never succeeded within {timeout_s}s (last error: {last_exc!r})")


_ROLE_PROPAGATION_FAILURE_PREFIXES = ("NO_WRITE_ACCESS_TO_OUTPUT", "NO_ACCESS_TO_INPUT")


def _retry_on_role_propagation_job_failure(start_and_poll, timeout_s: float):
    deadline = time.monotonic() + timeout_s
    while True:
        job_id, seen_statuses, final, fail_message = start_and_poll()
        if final == "COMPLETED":
            return job_id, seen_statuses, final, fail_message
        if not (fail_message or "").startswith(_ROLE_PROPAGATION_FAILURE_PREFIXES):
            return job_id, seen_statuses, final, fail_message
        if time.monotonic() >= deadline:
            return job_id, seen_statuses, final, fail_message
        time.sleep(2)


def _poll_job(ctx, job_id: str, timeout_s: float):
    comprehend = ctx.client("comprehend")
    terminal = {"COMPLETED", "FAILED", "STOPPED"}
    seen: list[str] = []
    deadline = time.monotonic() + timeout_s
    props = None
    while time.monotonic() < deadline:
        props = comprehend.describe_dominant_language_detection_job(JobId=job_id)[
            "DominantLanguageDetectionJobProperties"
        ]
        status = props["JobStatus"]
        if not seen or seen[-1] != status:
            seen.append(status)
        if status in terminal:
            return seen, status, props.get("Message")
        time.sleep(2)
    raise AssertionError(f"job never reached a terminal state within {timeout_s}s: saw {seen!r}")


def _wait_for_s3_object_under_prefix(ctx, bucket: str, prefix: str, timeout_s: float) -> str | None:
    s3 = ctx.client("s3")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        resp = s3.list_objects_v2(Bucket=bucket, Prefix=prefix)
        for obj in resp.get("Contents", []):
            if obj["Size"] > 0:
                return obj["Key"]
        time.sleep(5)
    return None


def _first_json_record_from_output(ctx, bucket: str, key: str) -> dict:
    s3 = ctx.client("s3")
    raw = s3.get_object(Bucket=bucket, Key=key)["Body"].read()
    with tarfile.open(fileobj=io.BytesIO(raw), mode="r:gz") as tar:
        for member in tar.getmembers():
            if not member.isfile():
                continue
            extracted = tar.extractfile(member)
            if extracted is None:
                continue
            for line in extracted.read().decode("utf-8").splitlines():
                line = line.strip()
                if line:
                    return json.loads(line)
    raise AssertionError(f"s3://{bucket}/{key} contained no JSON result lines")


def _setup_bucket_and_role(ctx) -> tuple[str, str]:
    s3 = ctx.client("s3")
    iam = ctx.client("iam")

    bucket = ctx.unique_name("sim2real-comprehend-").lower()
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region})
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(ctx, bucket))
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [{"Key": "sim2real-check", "Value": CHECK}]})

    role_name = ctx.unique_name("sim2real-comprehend-role-")
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "comprehend.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_policy),
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )
    role_arn = role["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))

    permission_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": ["s3:GetObject", "s3:ListBucket", "s3:PutObject"],
                "Resource": [f"arn:aws:s3:::{bucket}", f"arn:aws:s3:::{bucket}/*"],
            }
        ],
    }
    policy_name = "sim2real-comprehend-s3-access"
    iam.put_role_policy(RoleName=role_name, PolicyName=policy_name, PolicyDocument=json.dumps(permission_policy))
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name))

    return bucket, role_arn


def _empty_and_delete_bucket(ctx, bucket: str) -> None:
    s3 = ctx.client("s3")
    paginator = s3.get_paginator("list_objects_v2")
    for page in paginator.paginate(Bucket=bucket):
        objects = [{"Key": obj["Key"]} for obj in page.get("Contents", [])]
        if objects:
            failed = s3.delete_objects(Bucket=bucket, Delete={"Objects": objects}).get("Errors")
            if failed:
                raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
    s3.delete_bucket(Bucket=bucket)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
