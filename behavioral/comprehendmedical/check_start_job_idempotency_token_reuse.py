"""start-job-idempotency-token-reuse."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "start-job-idempotency-token-reuse"
GROUP = "state"
SERVICES = ["comprehendmedical"]

_INPUT_TEXT = "Patient was advised to continue current medication regimen."


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Reusing a ClientRequestToken with identical parameters returns the same JobId; reusing it with
    different parameters creates a second, independent job and leaves the first unaffected."""
    cm = ctx.client("comprehendmedical")
    bucket, role_arn = _create_bucket_and_role(ctx, _INPUT_TEXT)
    input_cfg = {"S3Bucket": bucket, "S3Key": "input/"}
    output_cfg = {"S3Bucket": bucket, "S3Key": "output/"}
    token = ctx.unique_name("sim2real-token-").replace("_", "-")

    job_id_1 = _start_job_with_role_retry(
        ctx, cm, ClientRequestToken=token, JobName="sim2real-idempotency-job",
        InputDataConfig=input_cfg, OutputDataConfig=output_cfg,
        DataAccessRoleArn=role_arn, LanguageCode="en",
    )
    ctx.on_cleanup(lambda: _best_effort_stop(ctx, job_id_1))

    # Representation depth: the job's representation in a List response must be structurally
    # identical (same field values) to its representation in a Describe response -- an emulator
    # that maintains two separate, drifting views of job state (e.g. a summary vs. a detail store)
    # would fail this cross-representation consistency check.
    describe_props = cm.describe_phi_detection_job(JobId=job_id_1)["ComprehendMedicalAsyncJobProperties"]
    list_entry = _find_list_entry(cm, job_id_1)
    assert list_entry is not None, f"job {job_id_1} did not appear in ListPHIDetectionJobs"
    for field in ("JobId", "JobName", "DataAccessRoleArn", "LanguageCode", "InputDataConfig", "OutputDataConfig"):
        assert list_entry.get(field) == describe_props.get(field), (
            f"List/Describe representation mismatch for {field}: "
            f"list={list_entry.get(field)!r} vs describe={describe_props.get(field)!r}"
        )
    # JobStatus is a live, mutable field -- both views must agree on it at the same point in time
    # (allowing for either SUBMITTED or IN_PROGRESS as sync, but never a mismatch between them).
    assert list_entry.get("JobStatus") == describe_props.get("JobStatus"), (
        f"List/Describe JobStatus disagreement: list={list_entry.get('JobStatus')!r} "
        f"vs describe={describe_props.get('JobStatus')!r}"
    )

    # Same token, identical parameters -> the create is idempotent, same JobId comes back.
    resp_repeat = cm.start_phi_detection_job(
        ClientRequestToken=token, JobName="sim2real-idempotency-job",
        InputDataConfig=input_cfg, OutputDataConfig=output_cfg,
        DataAccessRoleArn=role_arn, LanguageCode="en",
    )
    assert resp_repeat["JobId"] == job_id_1, (
        f"expected the same JobId for a repeated idempotency token, got {resp_repeat['JobId']} vs {job_id_1}"
    )

    # Same token, DIFFERENT parameters (different JobName) -> NOT rejected: a second, independent
    # job is created rather than the token deduplicating or the call being refused.
    resp_second = cm.start_phi_detection_job(
        ClientRequestToken=token, JobName="sim2real-idempotency-job-CHANGED",
        InputDataConfig=input_cfg, OutputDataConfig=output_cfg,
        DataAccessRoleArn=role_arn, LanguageCode="en",
    )
    job_id_2 = resp_second["JobId"]
    assert job_id_2 != job_id_1, (
        f"expected a distinct second job for a reused token with different params, got the same "
        f"JobId {job_id_1} back"
    )
    ctx.on_cleanup(lambda: _best_effort_stop(ctx, job_id_2))

    # Terminal read at an independent operation: the second job's own JobName was honored, not
    # discarded or merged into the first job's.
    second_props = cm.describe_phi_detection_job(JobId=job_id_2)["ComprehendMedicalAsyncJobProperties"]
    assert second_props["JobName"] == "sim2real-idempotency-job-CHANGED", (
        f"expected the second job's own JobName, got {second_props['JobName']!r}"
    )

    # Effect isolation: the original job's own configuration was not mutated by the second,
    # reused-token request.
    props = cm.describe_phi_detection_job(JobId=job_id_1)["ComprehendMedicalAsyncJobProperties"]
    assert props["JobName"] == "sim2real-idempotency-job", (
        f"expected original JobName to be untouched, got {props['JobName']}"
    )


# ===== helpers =====

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
    # S3 CreateBucket's own API quirk: LocationConstraint must be omitted for us-east-1 and is
    # required everywhere else. Not a hardcoded target region -- ctx.region drives both branches.
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region})
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(ctx, bucket))
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [{"Key": "sim2real:managed", "Value": "true"}]})
    s3.put_object(Bucket=bucket, Key="input/doc.txt", Body=text.encode("utf-8"))

    role_name = ctx.unique_name("sim2real-cmed-role-")
    role = iam.create_role(
        RoleName=role_name, AssumeRolePolicyDocument=_trust_policy(),
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
    )
    role_arn = role["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    iam.put_role_policy(RoleName=role_name, PolicyName="s3-access", PolicyDocument=_s3_access_policy(bucket))
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName="s3-access"))
    return bucket, role_arn


def _best_effort_stop(ctx, job_id: str) -> None:
    """Stop the job; one that is gone or already finished needs no stop, anything else raises."""
    client = ctx.client("comprehendmedical")
    try:
        client.stop_phi_detection_job(JobId=job_id)
    except ClientError as exc:
        code = exc.response["Error"]["Code"]
        if code == "ResourceNotFoundException":
            return
        if code != "InvalidRequestException":
            raise
        # Stopping a COMPLETED or FAILED job is refused with InvalidRequestException.
        status = client.describe_phi_detection_job(JobId=job_id)["ComprehendMedicalAsyncJobProperties"]["JobStatus"]
        if status not in ("COMPLETED", "PARTIAL_SUCCESS", "FAILED", "STOPPED", "STOP_REQUESTED"):
            raise


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
            return cm.start_phi_detection_job(**kwargs)["JobId"]
        except Exception as err:  # noqa: BLE001 - retry any failure until the deadline, then re-raise
            last_error = err
            time.sleep(interval_s)
    raise last_error


def _find_list_entry(cm, job_id: str, timeout_s: float = 60.0, interval_s: float = 5.0):
    """List can lag slightly behind a just-submitted job becoming visible; poll briefly."""
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        next_token = None
        while True:
            kwargs = {"MaxResults": 100}
            if next_token:
                kwargs["NextToken"] = next_token
            page = cm.list_phi_detection_jobs(**kwargs)
            for entry in page["ComprehendMedicalAsyncJobPropertiesList"]:
                if entry["JobId"] == job_id:
                    return entry
            next_token = page.get("NextToken")
            if not next_token:
                break
        time.sleep(interval_s)
    return None




if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
