"""untag-resource-nonexistent-resource-rejected."""
from __future__ import annotations

import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "untag-resource-nonexistent-resource-rejected"
GROUP = "error-semantics"
SERVICES = ["comprehend"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """UntagResource rejects a well-formed ResourceArn for a job that was never
    started with ResourceNotFoundException, while the identical call against a
    real, freshly-tagged job (the positive control) actually removes the tag."""
    comprehend = ctx.client("comprehend")
    infra = _create_job_infra(ctx, "This is a small sample document for key phrase analysis.\n")

    def _start():
        return comprehend.start_key_phrases_detection_job(
            InputDataConfig={"S3Uri": infra["input_s3_uri"], "InputFormat": "ONE_DOC_PER_LINE"},
            OutputDataConfig={"S3Uri": infra["output_s3_uri"]},
            DataAccessRoleArn=infra["role_arn"],
            LanguageCode="en",
        )

    real_job = _retry_start_job(_start)
    job_arn = real_job["JobArn"]
    ctx.on_cleanup(lambda: _best_effort_stop(ctx, real_job["JobId"]))

    # Positive control: tag/untag on a real job ARN actually works, so the
    # negative below cannot be explained by "UntagResource always fails".
    comprehend.tag_resource(ResourceArn=job_arn, Tags=[{"Key": "sim2real-env", "Value": "control"}])
    tagged = comprehend.list_tags_for_resource(ResourceArn=job_arn)["Tags"]
    assert {"Key": "sim2real-env", "Value": "control"} in tagged, tagged

    comprehend.untag_resource(ResourceArn=job_arn, TagKeys=["sim2real-env"])
    after_control = comprehend.list_tags_for_resource(ResourceArn=job_arn)["Tags"]
    assert after_control == [], f"expected the positive control's tag to be removed, got {after_control}"

    # Break the one thing: untag a well-formed ARN for a job id that was never started.
    fake_arn = f"{job_arn.rsplit('/', 1)[0]}/{uuid.uuid4().hex[:32]}"
    code, message = _error(lambda: comprehend.untag_resource(ResourceArn=fake_arn, TagKeys=["some-key"]))
    assert code == "ResourceNotFoundException", code
    assert message == "RESOURCE_NOT_FOUND: Could not find specified resource.", message

    # Terminal independent read at the destination: ListTagsForResource — a different
    # operation than the one that was rejected above — enforces the same existence
    # check rather than answering an empty tag set for an unknown ARN.
    list_code, list_message = _error(lambda: comprehend.list_tags_for_resource(ResourceArn=fake_arn))
    assert list_code == "ResourceNotFoundException", list_code
    assert list_message == "RESOURCE_NOT_FOUND: Could not find specified resource.", list_message


# ===== helpers =====
import json  # noqa: E402

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
    s3.put_object(Bucket=bucket, Key="input/doc.txt", Body=doc_text.encode("utf-8"))

    role_name = ctx.unique_name("sim2real-comprehend-role-")
    role = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=_TRUST_POLICY)
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
    import time

    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return start_fn()
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "InvalidRequestException" or time.monotonic() >= deadline:
                raise
            time.sleep(interval_s)


def _error(fn):
    """Call fn(); return its (code, message). An unexpected success raises, so an emulator
    that accepts what real AWS refuses fails loudly instead of reading as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


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
