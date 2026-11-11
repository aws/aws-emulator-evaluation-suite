"""create-model-invocation-job-malformed-s3-uri-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-model-invocation-job-malformed-s3-uri-rejected"
GROUP = "overly-permissive"
SERVICES = ["bedrock"]

_MODEL_ID = "moonshotai.kimi-k2.5"  # one of the few models with batch-inference support in us-west-2
_RECORD_COUNT = 100  # real AWS batch inference rejects a job with fewer records


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateModelInvocationJob rejects a malformed inputDataConfig S3 URI with ValidationException
    and creates no job, while a well-formed request with real S3 data and IAM role is accepted."""
    # The positive control starts a real batch inference job (costs money, needs model access);
    # it uses the documented minimum record count and is stopped on cleanup.
    bedrock = ctx.client("bedrock")
    s3 = ctx.client("s3")

    bucket_name = ctx.unique_name("sim2real-bedbatch-")
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket_name)
    else:
        s3.create_bucket(
            Bucket=bucket_name, CreateBucketConfiguration={"LocationConstraint": ctx.region}
        )
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(s3, bucket_name))

    input_key = "input/records.jsonl"
    lines = [
        json.dumps(
            {
                "recordId": f"REC{i:05d}",
                "modelInput": {
                    "anthropic_version": "bedrock-2023-05-31",
                    "max_tokens": 8,
                    "messages": [{"role": "user", "content": f"Say hi. (variant {i})"}],
                },
            }
        )
        for i in range(_RECORD_COUNT)
    ]
    s3.put_object(Bucket=bucket_name, Key=input_key, Body="\n".join(lines).encode("utf-8"))

    role_arn = _create_batch_role(ctx, bucket_name)
    model_arn = f"arn:aws:bedrock:{ctx.region}::foundation-model/{_MODEL_ID}"

    job_name_bad = ctx.unique_name("sim2real-badjob-")
    bad_code, bad_message = _error_code_and_message(
        lambda: bedrock.create_model_invocation_job(
            jobName=job_name_bad,
            roleArn=role_arn,
            modelId=model_arn,
            inputDataConfig={"s3InputDataConfig": {"s3Uri": "ftp://not-a-valid-s3-uri/records.jsonl"}},
            outputDataConfig={"s3OutputDataConfig": {"s3Uri": f"s3://{bucket_name}/output/"}},
        )
    )
    assert bad_code == "ValidationException", (
        f"expected a malformed inputDataConfig s3Uri to be rejected immediately "
        f"with ValidationException, got {bad_code!r}"
    )
    expected_message = (
        "1 validation error detected: Value at 'inputDataConfig.s3InputDataConfig.s3Uri' failed to "
        "satisfy constraint: Member must satisfy regular expression pattern: "
        "s3://[a-z0-9][-.a-z0-9]{1,61}[a-z0-9](?:/[-!_*'().a-z0-9A-Z]+(?:/[-!_*'().a-z0-9A-Z]+)*)?/?"
    )
    assert bad_message == expected_message, f"expected message {expected_message!r}, got {bad_message!r}"

    listed = bedrock.list_model_invocation_jobs(nameContains=job_name_bad).get("invocationJobSummaries", [])
    assert not listed, f"expected no job to have been created for the rejected request, found {listed!r}"

    # Positive control: identical shape with a well-formed s3Uri to real data.
    job_name_good = ctx.unique_name("sim2real-goodjob-")
    job_arn = _create_job_with_retries(
        bedrock,
        job_name=job_name_good,
        role_arn=role_arn,
        model_id=model_arn,
        input_uri=f"s3://{bucket_name}/{input_key}",
        output_uri=f"s3://{bucket_name}/output/",
    )
    assert job_arn, "expected the well-formed CreateModelInvocationJob request to return a jobArn"

    def _stop() -> None:
        """Stop the job unless it is gone or already terminal; any other failure raises."""
        try:
            bedrock.stop_model_invocation_job(jobIdentifier=job_arn)
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code == "ResourceNotFoundException":
                return
            if code != "ValidationException":
                raise
            status = bedrock.get_model_invocation_job(jobIdentifier=job_arn)["status"]
            if status not in ("Stopping", "Stopped", "Completed", "PartiallyCompleted", "Failed", "Expired"):
                raise

    ctx.on_cleanup(_stop)

    # Any later failure of the accepted job is deferred and out of scope here.
    status = bedrock.get_model_invocation_job(jobIdentifier=job_arn)["status"]
    assert status in ("Submitted", "Validating", "Scheduled", "InProgress", "Completed", "PartiallyCompleted"), (
        f"expected the well-formed job to be accepted and progressing normally, got status={status!r}"
    )


def _error_code_and_message(fn):
    """Call fn(); return its botocore error (code, message). An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message", "")
    raise AssertionError(f"expected this call to be rejected, but it SUCCEEDED and returned {result!r}")


def _create_job_with_retries(bedrock, *, job_name, role_arn, model_id, input_uri, output_uri, timeout_s=90.0):
    deadline = time.monotonic() + timeout_s
    last_err = None
    while time.monotonic() < deadline:
        try:
            resp = bedrock.create_model_invocation_job(
                jobName=job_name,
                roleArn=role_arn,
                modelId=model_id,
                inputDataConfig={"s3InputDataConfig": {"s3Uri": input_uri}},
                outputDataConfig={"s3OutputDataConfig": {"s3Uri": output_uri}},
            )
            return resp["jobArn"]
        except ClientError as err:
            last_err = err
            code = err.response["Error"]["Code"]
            if code in ("AccessDeniedException", "ResourceNotFoundException", "ValidationException"):
                time.sleep(5.0)
                continue
            raise
    raise last_err


def _create_batch_role(ctx, bucket_name):
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-batchrole-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "bedrock.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    role = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust))
    role_arn = role["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    policy_name = "s3-batch-access"
    policy_doc = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": ["s3:GetObject", "s3:ListBucket"],
                "Resource": [f"arn:aws:s3:::{bucket_name}", f"arn:aws:s3:::{bucket_name}/*"],
            },
            {
                "Effect": "Allow",
                "Action": ["s3:PutObject"],
                "Resource": [f"arn:aws:s3:::{bucket_name}/output/*"],
            },
        ],
    }
    iam.put_role_policy(RoleName=role_name, PolicyName=policy_name, PolicyDocument=json.dumps(policy_doc))
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name))
    return role_arn


def _empty_and_delete_bucket(s3, bucket_name):
    try:
        paginator = s3.get_paginator("list_objects_v2")
        for page in paginator.paginate(Bucket=bucket_name):
            objects = [{"Key": obj["Key"]} for obj in page.get("Contents", [])]
            if objects:
                failed = s3.delete_objects(Bucket=bucket_name, Delete={"Objects": objects}).get("Errors")
                if failed:
                    raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
    finally:
        s3.delete_bucket(Bucket=bucket_name)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
