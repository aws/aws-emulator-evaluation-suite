"""async-job-stop-transition-and-duplicate-stop-rejected."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "async-job-stop-transition-and-duplicate-stop-rejected"
GROUP = "state"
SERVICES = ["comprehendmedical"]

_INPUT_TEXT = "Patient reports mild fatigue and was advised to rest and stay hydrated."


def _error(fn):
    """Call fn(); return its ClientError (code, message). An unexpected success raises, so a
    target that accepts what AWS refuses fails loudly rather than as a code mismatch."""
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError but the call succeeded: {result!r}")


@tags("axis:rejection", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """StopEntitiesDetectionV2Job drives a running job to STOPPED, and stopping it again -- now
    that it is terminal -- is rejected rather than silently accepted."""
    cm = ctx.client("comprehendmedical")
    bucket, role_arn = _create_bucket_and_role(ctx, _INPUT_TEXT)
    # InputDataConfig.S3Key names the folder Comprehend Medical scans for input documents, not a
    # specific object key -- a direct file key is rejected with ResourceNotFoundException even
    # though the object exists at that key inside the folder.
    input_cfg = {"S3Bucket": bucket, "S3Key": "input/"}
    output_cfg = {"S3Bucket": bucket, "S3Key": "output/"}

    job_id = _start_job_with_role_retry(
        ctx, cm, InputDataConfig=input_cfg, OutputDataConfig=output_cfg,
        DataAccessRoleArn=role_arn, LanguageCode="en",
    )

    # Stop immediately, before the job can reach a terminal state on its own.
    cm.stop_entities_detection_v2_job(JobId=job_id)

    status = _poll_job_status(
        ctx, cm.describe_entities_detection_v2_job, job_id,
        acceptable={"STOPPED"}, timeout_s=600.0,
    )
    assert status == "STOPPED", f"expected job to transition to STOPPED, last observed status={status}"

    # Negative: the job is now terminal, so a second Stop is rejected.
    code, message = _error(lambda: cm.stop_entities_detection_v2_job(JobId=job_id))
    assert code == "InvalidRequestException", f"expected InvalidRequestException, got {code}"
    expected = "Job is already in terminal state."
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # Effect absent: the duplicate stop call did not change the job's state.
    props = cm.describe_entities_detection_v2_job(JobId=job_id)["ComprehendMedicalAsyncJobProperties"]
    assert props["JobStatus"] == "STOPPED", f"expected job to remain STOPPED, got {props['JobStatus']}"

    # Positive control: stopping a DIFFERENT, still-running job of the same type succeeds.
    job_id_2 = _start_job_with_role_retry(
        ctx, cm, InputDataConfig=input_cfg, OutputDataConfig=output_cfg,
        DataAccessRoleArn=role_arn, LanguageCode="en",
    )
    resp = cm.stop_entities_detection_v2_job(JobId=job_id_2)
    assert resp["JobId"] == job_id_2, f"expected stop response to echo JobId={job_id_2}, got {resp['JobId']}"

    # Independent read at the destination: the second job actually transitions to STOPPED too,
    # rather than the mutating call's own echoed response being the only evidence it worked.
    status_2 = _poll_job_status(
        ctx, cm.describe_entities_detection_v2_job, job_id_2,
        acceptable={"STOPPED"}, timeout_s=600.0,
    )
    assert status_2 == "STOPPED", (
        f"expected the still-running control job to transition to STOPPED, last observed status={status_2}"
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
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region})
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(ctx, bucket))
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [{"Key": "sim2real", "Value": CHECK}]})
    s3.put_object(Bucket=bucket, Key="input/doc.txt", Body=text.encode("utf-8"))

    role_name = ctx.unique_name("sim2real-cmed-role-")
    role = iam.create_role(
        RoleName=role_name, AssumeRolePolicyDocument=_trust_policy(),
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
    deadline = time.monotonic() + timeout_s
    last_error = None
    while time.monotonic() < deadline:
        try:
            return cm.start_entities_detection_v2_job(**kwargs)["JobId"]
        except Exception as err:  # noqa: BLE001 - retry any failure until the deadline, then re-raise
            last_error = err
            time.sleep(interval_s)
    raise last_error


def _poll_job_status(ctx, describe_fn, job_id: str, acceptable, timeout_s: float = 600.0, interval_s: float = 10.0) -> str:
    terminal = {"COMPLETED", "PARTIAL_SUCCESS", "FAILED", "STOPPED"}
    deadline = time.monotonic() + timeout_s
    last_status = None
    while time.monotonic() < deadline:
        props = describe_fn(JobId=job_id)["ComprehendMedicalAsyncJobProperties"]
        last_status = props["JobStatus"]
        if last_status in acceptable or last_status in terminal:
            return last_status
        time.sleep(interval_s)
    raise TimeoutError(
        f"job {job_id} did not reach {acceptable} or a terminal state within {timeout_s}s; "
        f"last observed status={last_status}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
