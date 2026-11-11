"""concurrent-start-job-same-token-idempotent-dedup."""
from __future__ import annotations

import time
from concurrent.futures import ThreadPoolExecutor

from behavioral_harness import tags

CHECK = "concurrent-start-job-same-token-idempotent-dedup"
GROUP = "concurrency"
SERVICES = ["comprehend"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Concurrent StartKeyPhrasesDetectionJob calls sharing one ClientRequestToken and identical
    parameters collapse to one JobId, confirmed by ListKeyPhrasesDetectionJobs listing one job."""
    comprehend = ctx.client("comprehend")
    infra = _create_job_infra(ctx, "This is a small sample document for key phrase analysis.\n")
    token = ctx.unique_name("sim2real-token-").replace("_", "-")
    job_name = ctx.unique_name("sim2real-kpj-").replace("_", "-")

    def _start():
        return comprehend.start_key_phrases_detection_job(
            InputDataConfig={"S3Uri": infra["input_s3_uri"], "InputFormat": "ONE_DOC_PER_LINE"},
            OutputDataConfig={"S3Uri": infra["output_s3_uri"]},
            DataAccessRoleArn=infra["role_arn"],
            LanguageCode="en",
            JobName=job_name,
            ClientRequestToken=token,
            Tags=[{"Key": "sim2real", "Value": CHECK}],
        )

    # First call also serves to absorb IAM role-propagation retries so the
    # concurrent race below is not confounded by transient InvalidRequestException.
    first = _retry_start_job(_start)
    ctx.on_cleanup(lambda: _best_effort_stop(ctx, first["JobId"]))

    with ThreadPoolExecutor(max_workers=5) as pool:
        futures = [pool.submit(_start) for _ in range(5)]
        job_ids = {first["JobId"]} | {f.result()["JobId"] for f in futures}

    assert job_ids == {first["JobId"]}, f"expected a single deduplicated JobId, got {job_ids}"

    # Independent read at the destination: confirm server-side that exactly one
    # job with this JobName exists, rather than trusting only the Start
    # responses' own echoed JobId back to each other.
    matches = []
    next_token = None
    for _ in range(50):
        kwargs = {"Filter": {"JobName": job_name}}
        if next_token:
            kwargs["NextToken"] = next_token
        resp = comprehend.list_key_phrases_detection_jobs(**kwargs)
        matches.extend(resp.get("KeyPhrasesDetectionJobPropertiesList", []))
        next_token = resp.get("NextToken")
        if not next_token:
            break
    matched_ids = {j["JobId"] for j in matches}
    assert matched_ids == {first["JobId"]}, (
        f"expected exactly one server-side job named {job_name!r} with JobId "
        f"{first['JobId']!r}, found {matched_ids!r}"
    )


# ===== helpers =====
import json  # noqa: E402
from botocore.exceptions import ClientError  # noqa: E402

_TRUST_POLICY = json.dumps(
    {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "comprehend.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
)


def _s3_policy(bucket: str) -> str:
    return json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": ["s3:GetObject", "s3:ListBucket"],
                    "Resource": [f"arn:aws:s3:::{bucket}", f"arn:aws:s3:::{bucket}/*"],
                },
                {
                    "Effect": "Allow",
                    "Action": ["s3:PutObject"],
                    "Resource": f"arn:aws:s3:::{bucket}/output/*",
                },
            ],
        }
    )


def _create_job_infra(ctx, doc_text: str) -> dict[str, str]:
    s3 = ctx.client("s3")
    iam = ctx.client("iam")
    bucket = ctx.unique_name("sim2real-comprehend").replace("_", "-").lower()
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region})
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(ctx, bucket))
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [{"Key": "sim2real", "Value": CHECK}]})
    s3.put_object(Bucket=bucket, Key="input/doc.txt", Body=doc_text.encode("utf-8"))

    role_name = ctx.unique_name("sim2real-comprehend-role-")
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=_TRUST_POLICY,
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    role_arn = role["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    iam.put_role_policy(RoleName=role_name, PolicyName="s3-access", PolicyDocument=_s3_policy(bucket))
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName="s3-access"))

    return {
        "bucket": bucket,
        "role_arn": role_arn,
        "input_s3_uri": f"s3://{bucket}/input/doc.txt",
        "output_s3_uri": f"s3://{bucket}/output/",
    }


def _empty_and_delete_bucket(ctx, bucket: str) -> None:
    s3 = ctx.client("s3")
    paginator = s3.get_paginator("list_objects_v2")
    for page in paginator.paginate(Bucket=bucket):
        for obj in page.get("Contents", []):
            s3.delete_object(Bucket=bucket, Key=obj["Key"])
    s3.delete_bucket(Bucket=bucket)


def _retry_start_job(start_fn, timeout_s: float = 90, interval_s: float = 5):
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return start_fn()
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "InvalidRequestException" or time.monotonic() >= deadline:
                raise
            time.sleep(interval_s)


def _best_effort_stop(ctx, job_id: str) -> None:
    """Stop the job; one that is gone or already finished needs no stop, anything else raises."""
    client = ctx.client("comprehend")
    try:
        client.stop_key_phrases_detection_job(JobId=job_id)
    except ClientError as exc:
        code = exc.response["Error"]["Code"]
        if code == "JobNotFoundException":
            return
        if code != "InvalidRequestException":
            raise
        # Stopping a COMPLETED or FAILED job is refused with InvalidRequestException.
        status = client.describe_key_phrases_detection_job(JobId=job_id)["KeyPhrasesDetectionJobProperties"]["JobStatus"]
        if status not in ("COMPLETED", "FAILED", "STOPPED", "STOP_REQUESTED"):
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
