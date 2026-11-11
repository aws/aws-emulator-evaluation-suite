"""async-phi-job-completes-and-writes-output-to-s3."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "async-phi-job-completes-and-writes-output-to-s3"
GROUP = "state"
SERVICES = ["comprehendmedical"]

_INPUT_TEXT = "Patient Jane Doe, age 52, was seen on 03/09/2023 for a routine follow-up visit."


@tags("axis:happy-path", "cap:c4", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """A PHI detection batch job transitions SUBMITTED -> COMPLETED and writes a real .out file
    to the output S3 bucket containing the same PHI entities a synchronous DetectPHI call would
    find in the same text."""
    cm = ctx.client("comprehendmedical")
    bucket, role_arn = _create_bucket_and_role(ctx, _INPUT_TEXT)
    # StartPHIDetectionJob's InputDataConfig.S3Key must be a folder (prefix): a direct file key
    # is rejected with ResourceNotFoundException ("the input S3 folder specified does not exist"),
    # confirmed against real AWS -- it processes every object under the prefix.
    input_cfg = {"S3Bucket": bucket, "S3Key": "input/"}
    output_cfg = {"S3Bucket": bucket, "S3Key": "output/"}

    job_id = _start_job_with_role_retry(
        ctx, cm, InputDataConfig=input_cfg, OutputDataConfig=output_cfg,
        DataAccessRoleArn=role_arn, LanguageCode="en",
    )

    status = _poll_job_status(ctx, cm.describe_phi_detection_job, job_id, timeout_s=900.0)
    assert status == "COMPLETED", f"expected job to reach COMPLETED, last observed status={status}"

    output = _find_output_with_entities(ctx, bucket, timeout_s=120.0)
    assert output is not None, "job reported COMPLETED but no .out file with Entities was found in the output bucket"

    entities = output["Entities"]
    assert any(e["Category"] == "PROTECTED_HEALTH_INFORMATION" for e in entities), (
        f"expected at least one PHI entity in batch output, got {entities}"
    )
    name_entities = [e for e in entities if e.get("Type") == "NAME"]
    assert any("Jane Doe" in e["Text"] for e in name_entities), (
        f"expected a NAME entity matching 'Jane Doe' in batch output, got {name_entities}"
    )


def _trust_policy() -> str:
    return json.dumps({
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"Service": "comprehendmedical.amazonaws.com"},
            "Action": "sts:AssumeRole",
        }],
    })


def _s3_access_policy(bucket: str) -> str:
    return json.dumps({
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Action": ["s3:GetObject"], "Resource": [f"arn:aws:s3:::{bucket}/*"]},
            {"Effect": "Allow", "Action": ["s3:ListBucket"], "Resource": [f"arn:aws:s3:::{bucket}"]},
            {"Effect": "Allow", "Action": ["s3:PutObject"], "Resource": [f"arn:aws:s3:::{bucket}/*"]},
        ],
    })


def _create_bucket_and_role(ctx, text: str):
    s3 = ctx.client("s3")
    iam = ctx.client("iam")

    bucket = ctx.unique_name("sim2real-cmed-").lower()
    # "us-east-1" here is the S3 CreateBucket API quirk (LocationConstraint must be omitted
    # only for that region), not a pinned target region -- the bucket itself lives in ctx.region.
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region})
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(ctx, bucket))
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [{"Key": "sim2real", "Value": CHECK}]})
    s3.put_object(Bucket=bucket, Key="input/doc.txt", Body=text.encode("utf-8"))

    role_name = ctx.unique_name("sim2real-cmed-role-")
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=_trust_policy(),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    role_arn = role["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    iam.put_role_policy(RoleName=role_name, PolicyName="s3-access", PolicyDocument=_s3_access_policy(bucket))
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName="s3-access"))
    return bucket, role_arn


def _empty_and_delete_bucket(ctx, bucket: str) -> None:
    s3 = ctx.client("s3")
    paginator = s3.get_paginator("list_objects_v2")
    for page in paginator.paginate(Bucket=bucket):
        for obj in page.get("Contents", []):
            s3.delete_object(Bucket=bucket, Key=obj["Key"])
    s3.delete_bucket(Bucket=bucket)


def _start_job_with_role_retry(ctx, cm, *, timeout_s: float = 180.0, interval_s: float = 8.0, **kwargs):
    """A freshly-created IAM role can take a few seconds to become assumable; retry Start until
    the role resolves rather than treating transient propagation lag as a genuine rejection."""
    deadline = time.monotonic() + timeout_s
    last_error = None
    while time.monotonic() < deadline:
        try:
            return cm.start_phi_detection_job(**kwargs)["JobId"]
        except Exception as err:  # noqa: BLE001 - retry any failure until the deadline, then re-raise
            last_error = err
            time.sleep(interval_s)
    raise last_error


def _poll_job_status(ctx, describe_fn, job_id: str, timeout_s: float = 900.0, interval_s: float = 15.0) -> str:
    terminal = {"COMPLETED", "PARTIAL_SUCCESS", "FAILED", "STOPPED"}
    deadline = time.monotonic() + timeout_s
    last_status = None
    while time.monotonic() < deadline:
        props = describe_fn(JobId=job_id)["ComprehendMedicalAsyncJobProperties"]
        last_status = props["JobStatus"]
        if last_status in terminal:
            return last_status
        time.sleep(interval_s)
    raise TimeoutError(
        f"job {job_id} did not reach a terminal state within {timeout_s}s; last observed status={last_status}"
    )


def _find_output_with_entities(ctx, bucket: str, timeout_s: float = 60.0, interval_s: float = 5.0):
    s3 = ctx.client("s3")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        paginator = s3.get_paginator("list_objects_v2")
        for page in paginator.paginate(Bucket=bucket, Prefix="output/"):
            for obj in page.get("Contents", []):
                key = obj["Key"]
                if not key.endswith(".out"):
                    continue
                body = s3.get_object(Bucket=bucket, Key=key)["Body"].read()
                try:
                    parsed = json.loads(body)
                except (json.JSONDecodeError, ValueError):
                    continue
                if isinstance(parsed, dict) and "Entities" in parsed:
                    return parsed
        time.sleep(interval_s)
    return None


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
