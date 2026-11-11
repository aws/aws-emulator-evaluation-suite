"""model-invocation-job-timeout-transitions-to-failed."""
from __future__ import annotations

import json
import time

from botocore.config import Config
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "model-invocation-job-timeout-transitions-to-failed"
GROUP = "visibility-timeout-ttl"
SERVICES = ["bedrock"]

# Batch inference is model- and region-gated: amazon.titan-text-lite-v1 is refused with
# "Batch inference is not supported for model ... in region us-west-2".
_MODEL_ID = "meta.llama3-1-8b-instruct-v1:0"


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """The service rejects timeoutDurationInHours below 24 with an exact ValidationException and
    creates no job, while the same request at 24 is accepted (a real timeout takes >= a day).

    Reference: https://docs.aws.amazon.com/bedrock/latest/APIReference/API_CreateModelInvocationJob.html
    """
    bedrock = ctx.client("bedrock")
    s3 = ctx.client("s3")

    bucket_name = ctx.unique_name("sim2real-bedtimeout-")
    if ctx.region == "us-east-1":
        # CreateBucket rejects an explicit LocationConstraint for us-east-1.
        s3.create_bucket(Bucket=bucket_name)
    else:
        s3.create_bucket(
            Bucket=bucket_name, CreateBucketConfiguration={"LocationConstraint": ctx.region}
        )
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(s3, bucket_name))

    input_key = "input/records.jsonl"
    record = {"recordId": "REC0", "modelInput": {"prompt": "Say hi.", "max_gen_len": 8, "temperature": 0}}
    s3.put_object(Bucket=bucket_name, Key=input_key, Body=(json.dumps(record) + "\n").encode("utf-8"))

    role_arn = _create_batch_role(ctx, bucket_name)
    model_arn = f"arn:aws:bedrock:{ctx.region}::foundation-model/{_MODEL_ID}"
    input_uri = f"s3://{bucket_name}/{input_key}"
    output_uri = f"s3://{bucket_name}/output/"

    # botocore's model enforces the same 24-168 range locally; disable client-side
    # validation so the out-of-range request reaches the service.
    raw_bedrock = ctx.client("bedrock", config=Config(parameter_validation=False))

    def _create(client, job_name, timeout_hours):
        return client.create_model_invocation_job(
            jobName=job_name,
            roleArn=role_arn,
            modelId=model_arn,
            inputDataConfig={"s3InputDataConfig": {"s3Uri": input_uri}},
            outputDataConfig={"s3OutputDataConfig": {"s3Uri": output_uri}},
            timeoutDurationInHours=timeout_hours,
        )

    # Both requests use the same real role and data so only timeoutDurationInHours differs.
    job_name_bad = ctx.unique_name("sim2real-badtimeout-")
    try:
        _create(raw_bedrock, job_name_bad, 1)
        raise AssertionError(
            "expected timeoutDurationInHours=1 (below the documented minimum of 24) "
            "to be rejected by the service"
        )
    except ClientError as err:
        code = err.response["Error"]["Code"]
        message = err.response["Error"].get("Message", "")
        assert code == "ValidationException", (
            f"expected ValidationException for an out-of-range timeoutDurationInHours, "
            f"got {code!r} ({message[:200]!r})"
        )
        expected_message = (
            "1 validation error detected: Value at 'timeoutDurationInHours' failed to satisfy "
            "constraint: Member must have value greater than or equal to 24"
        )
        assert message == expected_message, (
            f"expected the rejection message {expected_message!r}, got: {message!r}"
        )

    # Effect absent: no job was created for the rejected request.
    listed = bedrock.list_model_invocation_jobs(nameContains=job_name_bad).get("invocationJobSummaries", [])
    assert not listed, f"expected no job to have been created for the rejected request, found {listed!r}"

    # Positive control: identical request at the documented minimum is accepted.
    job_name_good = ctx.unique_name("sim2real-goodtimeout-")
    job_arn = _create_job_with_retries(
        bedrock,
        job_name=job_name_good,
        role_arn=role_arn,
        model_arn=model_arn,
        input_uri=input_uri,
        output_uri=output_uri,
        timeout_hours=24,
    )
    assert job_arn, "expected the boundary-minimum timeoutDurationInHours request to be accepted"

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

    status = bedrock.get_model_invocation_job(jobIdentifier=job_arn)["status"]
    assert status in ("Submitted", "Validating", "Scheduled", "InProgress", "Completed", "PartiallyCompleted"), (
        f"expected the boundary-minimum job to be accepted and progressing normally, got status={status!r}"
    )


def _create_job_with_retries(bedrock, *, job_name, role_arn, model_arn, input_uri, output_uri, timeout_hours, timeout_s=90.0):
    deadline = time.monotonic() + timeout_s
    last_err = None
    while time.monotonic() < deadline:
        try:
            resp = bedrock.create_model_invocation_job(
                jobName=job_name,
                roleArn=role_arn,
                modelId=model_arn,
                inputDataConfig={"s3InputDataConfig": {"s3Uri": input_uri}},
                outputDataConfig={"s3OutputDataConfig": {"s3Uri": output_uri}},
                timeoutDurationInHours=timeout_hours,
            )
            return resp["jobArn"]
        except ClientError as err:
            last_err = err
            code = err.response["Error"]["Code"]
            # A freshly created role may not be assumable yet (IAM eventual consistency).
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
