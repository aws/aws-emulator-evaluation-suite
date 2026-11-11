"""dominant-language-job-completes-writes-output."""
from __future__ import annotations

import io
import tarfile
import time
from typing import Any
from urllib.parse import urlparse

from behavioral_harness import tags

CHECK = "dominant-language-job-completes-writes-output"
GROUP = "job-lifecycle"
SERVICES = ["comprehend"]


@tags("axis:happy-path", "cap:c4", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """A StartDominantLanguageDetectionJob on an S3 input document reaches COMPLETED and writes an
    output.tar.gz whose first result line ranks "en" first."""
    comprehend = ctx.client("comprehend")
    infra = _create_job_infra(ctx, "The weather today is wonderful and sunny in Seattle.\n")

    def _start():
        return comprehend.start_dominant_language_detection_job(
            InputDataConfig={"S3Uri": infra["input_s3_uri"], "InputFormat": "ONE_DOC_PER_LINE"},
            OutputDataConfig={"S3Uri": infra["output_s3_uri"]},
            DataAccessRoleArn=infra["role_arn"],
        )

    def _describe(job_id):
        return comprehend.describe_dominant_language_detection_job(JobId=job_id)[
            "DominantLanguageDetectionJobProperties"
        ]

    props = _run_job_tolerating_iam_propagation(_start, _describe, timeout_s=1200, interval_s=15)
    assert props["JobStatus"] == "COMPLETED", props

    output_uri = props["OutputDataConfig"]["S3Uri"]
    parsed = urlparse(output_uri)
    s3 = ctx.client("s3")
    body = s3.get_object(Bucket=parsed.netloc, Key=parsed.path.lstrip("/"))["Body"].read()

    first_result = _first_json_record_from_tarball(body)
    assert first_result["Languages"][0]["LanguageCode"] == "en", first_result


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
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [{"Key": "sim2real", "Value": "true"}]})
    s3.put_object(Bucket=bucket, Key="input/doc.txt", Body=doc_text.encode("utf-8"))

    role_name = ctx.unique_name("sim2real-comprehend-role-")
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=_TRUST_POLICY,
        Tags=[{"Key": "sim2real", "Value": "true"}],
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
    # IAM role trust propagation is eventually consistent; Comprehend may reject
    # a brand-new role with InvalidRequestException for a short window after
    # creation, so poll for it to become usable instead of a single fixed sleep.
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return start_fn()
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "InvalidRequestException" or time.monotonic() >= deadline:
                raise
            time.sleep(interval_s)


def _poll_until_terminal(describe_fn, timeout_s: float, interval_s: float) -> dict[str, Any]:
    deadline = time.monotonic() + timeout_s
    props: dict[str, Any] = describe_fn()
    while props["JobStatus"] not in ("COMPLETED", "FAILED", "STOPPED"):
        if time.monotonic() >= deadline:
            raise AssertionError(f"job did not reach a terminal state within {timeout_s}s: {props}")
        time.sleep(interval_s)
        props = describe_fn()
    return props


def _run_job_tolerating_iam_propagation(
    start_fn, describe_fn, timeout_s: float, interval_s: float
) -> dict[str, Any]:
    # The synchronous StartJob call can succeed (past _retry_start_job's own IAM-propagation
    # window) while Comprehend's async preflight write-access check still hits a not-yet-replicated
    # inline policy, which fails the job fast with NO_WRITE_ACCESS_TO_OUTPUT. That is the same
    # eventual-consistency class _retry_start_job already guards, one step later in the pipeline,
    # so retry with a fresh job rather than treating it as a real access defect.
    deadline = time.monotonic() + timeout_s
    while True:
        start_resp = _retry_start_job(start_fn)
        job_id = start_resp["JobId"]
        remaining = max(deadline - time.monotonic(), interval_s)
        props = _poll_until_terminal(lambda: describe_fn(job_id), timeout_s=remaining, interval_s=interval_s)
        is_iam_propagation_failure = props["JobStatus"] == "FAILED" and str(
            props.get("Message", "")
        ).startswith("NO_WRITE_ACCESS_TO_OUTPUT")
        if not is_iam_propagation_failure or time.monotonic() >= deadline:
            return props
        time.sleep(interval_s)


def _first_json_record_from_tarball(raw_bytes: bytes) -> dict[str, Any]:
    with tarfile.open(fileobj=io.BytesIO(raw_bytes), mode="r:gz") as tar:
        for member in tar.getmembers():
            if not member.isfile():
                continue
            extracted = tar.extractfile(member)
            if extracted is None:
                continue
            content = extracted.read().decode("utf-8")
            for line in content.splitlines():
                line = line.strip()
                if line:
                    return json.loads(line)
    raise AssertionError("output.tar.gz contained no JSON result lines")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
