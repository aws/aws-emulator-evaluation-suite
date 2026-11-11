"""e2e-evaluation-job-runs-and-is-purged."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "e2e-evaluation-job-runs-and-is-purged"
GROUP = "state-machine"
SERVICES = ["bedrock"]

_MODEL_ID = "amazon.nova-lite-v1:0"


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """An automated evaluation job progresses through InProgress to Completed with retrievable
    results in S3, and BatchDeleteEvaluationJob purges it so GetEvaluationJob and
    ListEvaluationJobs stop returning it.
    """
    # An evaluation job runs for many minutes on the service's own clock; the batch-delete/purge
    # assertions are fast, the Completed + S3-output assertions wait on that runtime.
    bedrock = ctx.client("bedrock")
    s3 = ctx.client("s3")
    iam = ctx.client("iam")
    sts = ctx.client("sts")

    bucket = ctx.unique_name("sim2real-behav-evaljob-").replace("_", "-")
    _create_bucket(ctx, s3, bucket)
    role_arn = _create_evaluation_role(ctx, iam, sts, bucket)

    model_arn = f"arn:aws:bedrock:{ctx.region}::foundation-model/{_MODEL_ID}"
    job_name = ctx.unique_name("sim2real-behav-evaljob-")
    job_arn = _retry(
        lambda: bedrock.create_evaluation_job(
            jobName=job_name,
            roleArn=role_arn,
            evaluationConfig={
                "automated": {
                    "datasetMetricConfigs": [
                        {
                            "taskType": "QuestionAndAnswer",
                            "dataset": {"name": "Builtin.BoolQ"},
                            "metricNames": ["Builtin.Accuracy"],
                        }
                    ]
                }
            },
            inferenceConfig={"models": [{"bedrockModel": {"modelIdentifier": model_arn}}]},
            outputDataConfig={"s3Uri": f"s3://{bucket}/eval-output/"},
            jobTags=[{"key": "sim2real:managed", "value": "true"}, {"key": "sim2real:check", "value": CHECK}],
        )["jobArn"],
        retryable_codes=("AccessDeniedException", "ValidationException"),
    )
    ctx.on_cleanup(lambda: _ignore_conflict(lambda: bedrock.stop_evaluation_job(jobIdentifier=job_arn)))

    job = _poll_until(
        lambda: bedrock.get_evaluation_job(jobIdentifier=job_arn),
        lambda j: j["status"] in ("Completed", "Failed", "Stopped"),
        timeout_s=5400,
        interval_s=60,
    )
    assert job["status"] == "Completed", f"evaluation job did not complete: {job.get('failureMessages')}"

    listed = s3.list_objects_v2(Bucket=bucket, Prefix="eval-output/")
    assert listed.get("KeyCount", 0) > 0, "expected retrievable evaluation output objects in S3"

    delete_resp = bedrock.batch_delete_evaluation_job(jobIdentifiers=[job_arn])
    assert delete_resp["errors"] == [], f"expected no batch-delete errors, got {delete_resp['errors']}"
    # BatchDeleteEvaluationJob echoes the bare job id (the last ARN segment), not the ARN passed
    # in, unlike the ARN-shaped pattern in the service model.
    job_id = job_arn.rsplit("/", 1)[-1]
    assert any(item["jobIdentifier"] == job_id for item in delete_resp["evaluationJobs"]), (
        f"expected job id {job_id!r} in batch-delete response, got {delete_resp['evaluationJobs']}"
    )

    _poll_until(
        lambda: _probe_code(lambda: bedrock.get_evaluation_job(jobIdentifier=job_arn)),
        lambda code: code == "ResourceNotFoundException",
        timeout_s=120,
        interval_s=5,
    )

    remaining = bedrock.list_evaluation_jobs()["jobSummaries"]
    assert job_arn not in {j["jobArn"] for j in remaining}, f"expected {job_arn} absent from list_evaluation_jobs, still listed"


# ===== helpers =====
def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last value: {last}")


def _retry(fn, *, retryable_codes, timeout_s=60.0, interval_s=4.0):
    deadline = time.monotonic() + timeout_s
    last_err = None
    while time.monotonic() < deadline:
        try:
            return fn()
        except ClientError as err:
            code = err.response["Error"]["Code"]
            if code in retryable_codes:
                last_err = err
                time.sleep(interval_s)
                continue
            raise
    raise AssertionError(f"operation never succeeded: {last_err}")


def _probe_code(fn):
    """The error code fn() raises; while the purge is still propagating the call succeeds and
    this returns the "present" marker, which no error code equals, so the poll keeps waiting
    and a timeout names it."""
    try:
        fn()
    except ClientError as err:
        return err.response["Error"]["Code"]
    return "present"


def _ignore_conflict(fn):
    try:
        fn()
    except ClientError as err:
        if err.response["Error"]["Code"] not in ("ConflictException", "ResourceNotFoundException"):
            raise


def _create_bucket(ctx, s3, bucket):
    region = ctx.region
    if region == "us-east-1":
        # us-east-1 is CreateBucket's own region-pinned special case: passing a
        # LocationConstraint there is rejected, so the literal names that quirk, not this check's region.
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": region})
    ctx.on_cleanup(lambda: _delete_bucket(s3, bucket))
    s3.put_bucket_tagging(
        Bucket=bucket,
        Tagging={"TagSet": [{"Key": "sim2real:managed", "Value": "true"}, {"Key": "sim2real:check", "Value": CHECK}]},
    )


def _delete_bucket(s3, bucket):
    paginator = s3.get_paginator("list_objects_v2")
    for page in paginator.paginate(Bucket=bucket):
        for obj in page.get("Contents", []):
            s3.delete_object(Bucket=bucket, Key=obj["Key"])
    s3.delete_bucket(Bucket=bucket)


def _create_evaluation_role(ctx, iam, sts, bucket):
    account_id = sts.get_caller_identity()["Account"]
    role_name = ctx.unique_name("sim2real-behav-evalrole-")
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "bedrock.amazonaws.com"},
                "Action": "sts:AssumeRole",
                "Condition": {"StringEquals": {"aws:SourceAccount": account_id}},
            }
        ],
    }
    iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_policy),
        Tags=[{"Key": "sim2real:managed", "Value": "true"}, {"Key": "sim2real:check", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: _delete_role(iam, role_name))

    access_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": ["s3:PutObject", "s3:GetObject", "s3:ListBucket"],
                "Resource": [f"arn:aws:s3:::{bucket}", f"arn:aws:s3:::{bucket}/*"],
            },
            {
                "Effect": "Allow",
                "Action": ["bedrock:InvokeModel", "bedrock:GetFoundationModel"],
                "Resource": ["*"],
            },
        ],
    }
    iam.put_role_policy(RoleName=role_name, PolicyName="eval-access", PolicyDocument=json.dumps(access_policy))
    return iam.get_role(RoleName=role_name)["Role"]["Arn"]


def _delete_role(iam, role_name):
    try:
        iam.delete_role_policy(RoleName=role_name, PolicyName="eval-access")
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise
    iam.delete_role(RoleName=role_name)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
