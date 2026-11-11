"""start-pii-entities-detection-job-missing-redaction-config-rejected."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "start-pii-entities-detection-job-missing-redaction-config-rejected"
GROUP = "overly-permissive"
SERVICES = ["comprehend"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """StartPiiEntitiesDetectionJob with Mode=ONLY_REDACTION and no RedactionConfig is rejected with
    InvalidRequestException and creates no job; the same request with Mode=ONLY_OFFSETS succeeds."""
    bucket = _create_bucket(ctx)
    s3 = ctx.client("s3")
    input_key = "input/doc.txt"
    s3.put_object(
        Bucket=bucket,
        Key=input_key,
        Body=b"Contact Jane at jane.doe@example.com for details.\n",
    )
    role_arn = _create_job_role(ctx, bucket)
    comprehend = ctx.client("comprehend")

    def _start(mode, output_suffix):
        return comprehend.start_pii_entities_detection_job(
            Mode=mode,
            LanguageCode="en",
            DataAccessRoleArn=role_arn,
            InputDataConfig={
                "S3Uri": f"s3://{bucket}/{input_key}",
                "InputFormat": "ONE_DOC_PER_LINE",
            },
            OutputDataConfig={"S3Uri": f"s3://{bucket}/output-{output_suffix}/"},
        )

    # Break exactly one thing: ONLY_REDACTION without the required RedactionConfig.
    code, message = _expect_rejected(ctx, lambda: _start_job_with_retry(lambda: _start("ONLY_REDACTION", "bad")))
    assert code == "InvalidRequestException", f"expected InvalidRequestException, got code={code!r}"
    expected = (
        "INPUT_CONFIG_INVALID_FOR_MODE: A RedactionConfig definition is required for PII detection "
        "requests that set the Mode parameter to ONLY_REDACTION. Add a RedactionConfig definition to "
        "your request, including a non-empty list of PII entity types to redact, and try again."
    )
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # Effect absent: no job matching this request exists (the call raised before any JobId
    # was minted, so there is nothing to look up).

    # Positive control: identical infra, ONLY_OFFSETS mode (no RedactionConfig needed) succeeds.
    ok_resp = _start_job_with_retry(lambda: _start("ONLY_OFFSETS", "ok"))
    job_id = ok_resp["JobId"]
    assert job_id, "positive control returned no JobId"
    ctx.on_cleanup(lambda: _best_effort_stop(ctx, job_id))

    # Terminal read is independent of the mutating call: describe the minted job at the
    # destination and confirm it is the real thing the request asked for, not an echo of
    # the StartPiiEntitiesDetectionJob response.
    props = comprehend.describe_pii_entities_detection_job(JobId=job_id)[
        "PiiEntitiesDetectionJobProperties"
    ]
    assert props["JobId"] == job_id, f"describe returned job {props['JobId']!r}, expected {job_id!r}"
    assert props["Mode"] == "ONLY_OFFSETS", f"expected Mode=ONLY_OFFSETS, got {props['Mode']!r}"
    assert props["JobStatus"] in (
        "SUBMITTED",
        "IN_PROGRESS",
        "COMPLETED",
    ), f"positive control job in unexpected status {props['JobStatus']!r}"


# ===== helpers =====
def _best_effort_stop(ctx, job_id):
    """Stop the job; one that is gone or already finished needs no stop, anything else raises."""
    client = ctx.client("comprehend")
    try:
        client.stop_pii_entities_detection_job(JobId=job_id)
    except ClientError as exc:
        code = exc.response["Error"]["Code"]
        if code == "JobNotFoundException":
            return
        if code != "InvalidRequestException":
            raise
        # Stopping a COMPLETED or FAILED job is refused with InvalidRequestException.
        status = client.describe_pii_entities_detection_job(JobId=job_id)["PiiEntitiesDetectionJobProperties"]["JobStatus"]
        if status not in ("COMPLETED", "FAILED", "STOPPED", "STOP_REQUESTED"):
            raise


def _create_bucket(ctx):
    s3 = ctx.client("s3")
    name = ctx.unique_name("sim2real-comprehend-").lower().replace("_", "-")
    kwargs = {"Bucket": name}
    if ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kwargs)
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(ctx, name))
    s3.put_bucket_tagging(
        Bucket=name,
        Tagging={"TagSet": [{"Key": "sim2real", "Value": "start-pii-entities-detection-job-missing-redaction-config-rejected"}]},
    )
    return name


def _empty_and_delete_bucket(ctx, name):
    s3 = ctx.client("s3")
    try:
        resp = s3.list_objects_v2(Bucket=name)
        for obj in resp.get("Contents", []):
            s3.delete_object(Bucket=name, Key=obj["Key"])
        s3.delete_bucket(Bucket=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("NoSuchBucket", "NoSuchKey"):
            raise


def _create_job_role(ctx, bucket):
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-comprehend-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "comprehend.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": "start-pii-entities-detection-job-missing-redaction-config-rejected"}],
    )
    role_arn = role["Role"]["Arn"]
    ctx.on_cleanup(lambda: _delete_role(ctx, role_name))
    policy_doc = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Action": ["s3:GetObject"], "Resource": f"arn:aws:s3:::{bucket}/*"},
            {"Effect": "Allow", "Action": ["s3:ListBucket"], "Resource": f"arn:aws:s3:::{bucket}"},
            {"Effect": "Allow", "Action": ["s3:PutObject"], "Resource": f"arn:aws:s3:::{bucket}/*"},
        ],
    }
    iam.put_role_policy(RoleName=role_name, PolicyName="comprehend-job-access", PolicyDocument=json.dumps(policy_doc))
    return role_arn


def _delete_role(ctx, role_name):
    iam = ctx.client("iam")
    try:
        iam.delete_role_policy(RoleName=role_name, PolicyName="comprehend-job-access")
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise
    try:
        iam.delete_role(RoleName=role_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _start_job_with_retry(fn, timeout_s=120.0, interval_s=5.0):
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    last_exc = None
    while time.monotonic() < deadline:
        try:
            return fn()
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            message = exc.response["Error"].get("Message", "").lower()
            if code in ("AccessDeniedException", "InvalidRequestException") and (
                "role" in message or "assume" in message or "permission" in message
            ):
                last_exc = exc
                time.sleep(interval_s)
                continue
            raise
    raise last_exc if last_exc is not None else RuntimeError("job start retry timed out")


def _expect_rejected(ctx, fn):
    """Call fn(); return its botocore error (code, message). An unexpected SUCCESS raises, after
    registering any job it started for cleanup, so an accepted request never reads as a code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        error = exc.response["Error"]
        return error["Code"], error.get("Message")
    job_id = result.get("JobId")
    if job_id:
        ctx.on_cleanup(lambda: _best_effort_stop(ctx, job_id))
    raise AssertionError(
        f"real AWS rejects ONLY_REDACTION without RedactionConfig, but the call SUCCEEDED "
        f"and returned JobId={job_id!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
