"""translation-job-stop-transitions-to-stopped."""
from __future__ import annotations

import json
import time
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "translation-job-stop-transitions-to-stopped"
GROUP = "state"
SERVICES = ["translate"]


@tags("axis:happy-path", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """StopTextTranslationJob, called right after a job is submitted, drives it to the STOPPED terminal
    state rather than letting it run to completion."""
    translate = ctx.client("translate")
    bucket = _create_bucket(ctx)
    _put_input_object(ctx, bucket, "input/doc.txt", "Hello world, this is a test document.")
    role_arn = _create_translate_role(ctx, bucket)

    client_token = uuid.uuid4().hex
    start_resp = _start_job_with_role_retry(
        translate,
        InputDataConfig={"S3Uri": f"s3://{bucket}/input/", "ContentType": "text/plain"},
        OutputDataConfig={"S3Uri": f"s3://{bucket}/output/"},
        DataAccessRoleArn=role_arn,
        SourceLanguageCode="en",
        TargetLanguageCodes=["es"],
        ClientToken=client_token,
    )
    job_id = start_resp["JobId"]
    assert start_resp["JobStatus"] == "SUBMITTED", f"expected SUBMITTED right after start, got {start_resp['JobStatus']!r}"

    # stop immediately, well before a trivial job could plausibly complete
    translate.stop_text_translation_job(JobId=job_id)

    final_status = _poll_until_terminal(ctx, job_id, timeout_s=900, interval_s=15)
    assert final_status == "STOPPED", f"expected StopTextTranslationJob to drive the job to STOPPED, got {final_status!r}"


def _create_bucket(ctx) -> str:
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-translate-").lower().replace("_", "-")
    kwargs = {"Bucket": bucket}
    # CreateBucket rejects an explicit LocationConstraint for us-east-1; every other region requires one.
    if ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kwargs)
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [{"Key": "sim2real", "Value": CHECK}]})
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(ctx, bucket))
    return bucket


def _empty_and_delete_bucket(ctx, bucket: str) -> None:
    s3 = ctx.client("s3")
    paginator = s3.get_paginator("list_objects_v2")
    for page in paginator.paginate(Bucket=bucket):
        for obj in page.get("Contents", []):
            s3.delete_object(Bucket=bucket, Key=obj["Key"])
    s3.delete_bucket(Bucket=bucket)


def _put_input_object(ctx, bucket: str, key: str, body: str) -> None:
    s3 = ctx.client("s3")
    s3.put_object(Bucket=bucket, Key=key, Body=body.encode("utf-8"), ContentType="text/plain")


def _create_translate_role(ctx, bucket: str) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-translate-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "translate.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))

    policy_doc = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Action": ["s3:GetObject"], "Resource": f"arn:aws:s3:::{bucket}/input/*"},
            {"Effect": "Allow", "Action": ["s3:ListBucket"], "Resource": f"arn:aws:s3:::{bucket}"},
            {"Effect": "Allow", "Action": ["s3:PutObject"], "Resource": f"arn:aws:s3:::{bucket}/output/*"},
        ],
    }
    policy_name = ctx.unique_name("sim2real-translate-policy-")
    iam.put_role_policy(RoleName=role_name, PolicyName=policy_name, PolicyDocument=json.dumps(policy_doc))
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name))
    return role["Arn"]


def _start_job_with_role_retry(translate, timeout_s: float = 90.0, interval_s: float = 5.0, **kwargs):
    """Poll the actual StartTextTranslationJob call until IAM role propagation catches up."""
    deadline = time.monotonic() + timeout_s
    last_err: ClientError | None = None
    while time.monotonic() < deadline:
        try:
            return translate.start_text_translation_job(**kwargs)
        except ClientError as e:
            if e.response["Error"]["Code"] != "InvalidRequestException":
                raise
            last_err = e
            time.sleep(interval_s)
    raise last_err


def _poll_until_terminal(ctx, job_id: str, timeout_s: float, interval_s: float) -> str:
    translate = ctx.client("translate")
    terminal = {"COMPLETED", "COMPLETED_WITH_ERROR", "FAILED", "STOPPED"}
    deadline = time.monotonic() + timeout_s
    status = "SUBMITTED"
    while time.monotonic() < deadline:
        status = translate.describe_text_translation_job(JobId=job_id)["TextTranslationJobProperties"][
            "JobStatus"
        ]
        if status in terminal:
            return status
        time.sleep(interval_s)
    raise AssertionError(f"job {job_id} never reached a terminal state, last status was {status}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
