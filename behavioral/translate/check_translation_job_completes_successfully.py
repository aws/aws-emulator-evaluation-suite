"""translation-job-completes-successfully."""
from __future__ import annotations

import json
import time
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "translation-job-completes-successfully"
GROUP = "state"
SERVICES = ["translate"]
_INPUT_TEXT = "Hello world, this is a test document."


@tags("axis:happy-path", "cap:c4", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """StartTextTranslationJob drives a batch job from SUBMITTED through IN_PROGRESS to COMPLETED, and the
    output S3 location actually receives translated output -- not just a status flip."""
    translate = ctx.client("translate")
    bucket = _create_bucket(ctx)
    _put_input_object(ctx, bucket, "input/doc.txt", _INPUT_TEXT)
    role_arn = _create_translate_role(ctx, bucket)

    # Translate assumes the role at job start, and a just-attached inline policy can still be
    # invisible to it then: the job FAILS with NO_READ/NO_WRITE_ACCESS. Rerun it, bounded, on
    # exactly that failure until IAM has propagated the policy.
    for _ in range(4):
        start_resp = _start_job_with_role_retry(
            translate,
            InputDataConfig={"S3Uri": f"s3://{bucket}/input/", "ContentType": "text/plain"},
            OutputDataConfig={"S3Uri": f"s3://{bucket}/output/"},
            DataAccessRoleArn=role_arn,
            SourceLanguageCode="en",
            TargetLanguageCodes=["es"],
            ClientToken=uuid.uuid4().hex,
        )
        job_id = start_resp["JobId"]
        assert start_resp["JobStatus"] == "SUBMITTED", f"expected SUBMITTED right after start, got {start_resp['JobStatus']!r}"

        final_props = _poll_until_terminal(ctx, job_id, timeout_s=1500, interval_s=2)
        message = final_props.get("Message") or ""
        if final_props["JobStatus"] != "FAILED" or not message.startswith(("NO_WRITE_ACCESS", "NO_READ_ACCESS")):
            break
        time.sleep(2)
    final_status = final_props["JobStatus"]
    assert final_status == "COMPLETED", (
        f"job {job_id} reached terminal state {final_status!r}, expected COMPLETED "
        f"(message={final_props.get('Message')!r})"
    )

    s3 = ctx.client("s3")
    output_objects = s3.list_objects_v2(Bucket=bucket, Prefix="output/").get("Contents", [])
    assert len(output_objects) > 0, f"expected translated output under s3://{bucket}/output/, found none"

    translated_keys = [obj["Key"] for obj in output_objects if obj["Key"].endswith("doc.txt")]
    assert translated_keys, f"no output key ends in doc.txt among {[o['Key'] for o in output_objects]}"
    translated_body = s3.get_object(Bucket=bucket, Key=translated_keys[0])["Body"].read()
    assert translated_body, f"translated object {translated_keys[0]} is empty"
    assert translated_body != _INPUT_TEXT.encode("utf-8"), (
        f"translated object {translated_keys[0]} is byte-identical to the untranslated English "
        "input -- expected Spanish-translated content"
    )


# ===== helpers =====


def _create_bucket(ctx) -> str:
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-translate-").lower().replace("_", "-")
    kwargs = {"Bucket": bucket}
    if ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kwargs)
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(ctx, bucket))
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [{"Key": "sim2real", "Value": CHECK}]})
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
            # Translate's documented data-access policy reads both the input and output prefixes.
            {"Effect": "Allow", "Action": ["s3:GetObject"], "Resource": f"arn:aws:s3:::{bucket}/*"},
            {"Effect": "Allow", "Action": ["s3:ListBucket"], "Resource": f"arn:aws:s3:::{bucket}"},
            {"Effect": "Allow", "Action": ["s3:PutObject"], "Resource": f"arn:aws:s3:::{bucket}/output/*"},
        ],
    }
    policy_name = ctx.unique_name("sim2real-translate-policy-")
    iam.put_role_policy(RoleName=role_name, PolicyName=policy_name, PolicyDocument=json.dumps(policy_doc))
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name))
    return role["Arn"]


def _start_job_with_role_retry(translate, timeout_s: float = 240.0, interval_s: float = 2.0, **kwargs):
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


def _poll_until_terminal(ctx, job_id: str, timeout_s: float, interval_s: float) -> dict:
    translate = ctx.client("translate")
    terminal = {"COMPLETED", "COMPLETED_WITH_ERROR", "FAILED", "STOPPED"}
    deadline = time.monotonic() + timeout_s
    props = {"JobStatus": "SUBMITTED"}
    while time.monotonic() < deadline:
        props = translate.describe_text_translation_job(JobId=job_id)["TextTranslationJobProperties"]
        if props["JobStatus"] in terminal:
            return props
        time.sleep(interval_s)
    raise AssertionError(f"job {job_id} never reached a terminal state, last status was {props['JobStatus']}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
