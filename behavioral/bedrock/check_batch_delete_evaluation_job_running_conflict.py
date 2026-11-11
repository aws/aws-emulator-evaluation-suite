"""batch-delete-evaluation-job-running-conflict."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "batch-delete-evaluation-job-running-conflict"
GROUP = "error-semantics"
SERVICES = ["bedrock"]

_MODEL_SHORT_ID = "amazon.nova-lite-v1:0"


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """BatchDeleteEvaluationJob rejects an InProgress job with a top-level ValidationException,
    not an `errors` entry, and deletes the job once it has reached a terminal state."""
    from botocore.exceptions import ClientError

    bedrock = ctx.client("bedrock")
    region = ctx.region
    bucket = _create_s3_bucket(ctx)
    role_arn = _create_eval_role(ctx, bucket, region)
    model_arn = f"arn:aws:bedrock:{region}::foundation-model/{_MODEL_SHORT_ID}"

    job_name = ctx.unique_name("sim2real-eval-")
    job = _retry_transient_access_denied(
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
            outputDataConfig={"s3Uri": f"s3://{bucket}/eval-out/"},
        )
    )
    job_arn = job["jobArn"]
    # StopEvaluationJob answers ValidationException for a job already in a terminal state.
    ctx.on_cleanup(
        lambda: _safe_call(
            lambda: bedrock.stop_evaluation_job(jobIdentifier=job_arn),
            "ResourceNotFoundException",
            "ValidationException",
        )
    )

    initial = bedrock.get_evaluation_job(jobIdentifier=job_arn)
    assert initial["status"] in ("InProgress",), f"expected a freshly created job to be InProgress, got {initial['status']}"

    try:
        rejected_resp = bedrock.batch_delete_evaluation_job(jobIdentifiers=[job_arn])
    except ClientError as e:
        code = e.response["Error"]["Code"]
        message = e.response["Error"]["Message"]
        assert code == "ValidationException", (
            f"expected ValidationException rejecting a still-InProgress job, got {code}: {message}"
        )
        assert message == (
            "All provided evaluation jobs in the request are not supported by batch deletion. "
            "Please re-submit with evaluation jobs that exists and under FAILED COMPLETED STOPPED status."
        ), (
            f"expected the rejection to name the terminal statuses it requires, got: {message}"
        )
    else:
        raise AssertionError(
            f"expected BatchDeleteEvaluationJob to reject a still-InProgress job with a top-level "
            f"ValidationException, but it returned a response: {rejected_resp}"
        )

    # Effect absent: the job itself is untouched.
    still_there = bedrock.get_evaluation_job(jobIdentifier=job_arn)
    assert still_there["jobArn"] == job_arn, f"expected {job_arn} to still be gettable after the rejected delete, got {still_there.get('jobArn')}"

    # Positive control: once actually stopped (a real terminal state), the batch delete succeeds.
    bedrock.stop_evaluation_job(jobIdentifier=job_arn)
    _wait_for_status(ctx, job_arn, {"Stopped", "Failed", "Completed"})

    # evaluationJobs/errors entries key on the short job id, not the ARN that was sent.
    job_id = job_arn.rsplit("/", 1)[-1]
    resp2 = bedrock.batch_delete_evaluation_job(jobIdentifiers=[job_arn])
    deleted2 = [d for d in resp2["evaluationJobs"] if d["jobIdentifier"] == job_id]
    errored2 = [e for e in resp2["errors"] if e["jobIdentifier"] == job_id]
    assert errored2 == [], f"expected no error deleting the now-terminal job, got {errored2}"
    assert len(deleted2) == 1, f"expected the terminal job to be accepted for deletion, got {resp2}"
    # Deletion is asynchronous (HTTP 202, jobStatus Deleting) -- an independent read must
    # eventually confirm the job is actually gone, not just accepted.
    _wait_for_deletion(ctx, job_arn)


def _mgmt_tags_kv():
    return [{"Key": "sim2real:managed", "Value": "true"}, {"Key": "sim2real:prefix", "Value": "sim2real-bedrock"}]


def _safe_call(fn, *gone_codes):
    """Run a teardown call; return only on the codes saying the resource is already gone."""
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as e:
        if e.response["Error"]["Code"] not in gone_codes:
            raise


def _retry_transient_access_denied(fn, timeout_s=60.0):
    from botocore.exceptions import ClientError

    # A freshly created IAM role is not always immediately assumable; Bedrock surfaces that
    # transient IAM-propagation window as either AccessDeniedException or ValidationException.
    deadline = time.monotonic() + timeout_s
    last_err = None
    while time.monotonic() < deadline:
        try:
            return fn()
        except ClientError as e:
            if e.response["Error"]["Code"] not in ("AccessDeniedException", "ValidationException"):
                raise
            last_err = e
            time.sleep(3.0)
    raise AssertionError(f"role still not assumable after {timeout_s}s: {last_err}")


def _create_s3_bucket(ctx) -> str:
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-bedrock-").lower().replace("_", "-")
    # us-east-1 is the one region where CreateBucket rejects an explicit LocationConstraint.
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(
            Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region}
        )
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": _mgmt_tags_kv()})

    def _cleanup():
        objs = s3.list_objects_v2(Bucket=bucket).get("Contents", [])
        if objs:
            failed = s3.delete_objects(
                Bucket=bucket, Delete={"Objects": [{"Key": o["Key"]} for o in objs]}
            ).get("Errors")
            if failed:
                raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
        s3.delete_bucket(Bucket=bucket)

    ctx.on_cleanup(lambda: _safe_call(_cleanup, "NoSuchBucket"))
    return bucket


def _create_eval_role(ctx, bucket: str, region: str) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-bedrock-eval-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "bedrock.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    role_arn = iam.create_role(
        RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust), Tags=_mgmt_tags_kv()
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: _safe_call(lambda: iam.delete_role(RoleName=role_name), "NoSuchEntity"))

    policy_name = f"{role_name}-policy"
    policy_doc = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": ["s3:GetObject", "s3:PutObject", "s3:ListBucket"],
                "Resource": [f"arn:aws:s3:::{bucket}", f"arn:aws:s3:::{bucket}/*"],
            },
            {
                "Effect": "Allow",
                "Action": ["bedrock:InvokeModel"],
                "Resource": f"arn:aws:bedrock:{region}::foundation-model/{_MODEL_SHORT_ID}",
            },
        ],
    }
    iam.put_role_policy(RoleName=role_name, PolicyName=policy_name, PolicyDocument=json.dumps(policy_doc))
    ctx.on_cleanup(
        lambda: _safe_call(
            lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name), "NoSuchEntity"
        )
    )
    return role_arn


def _wait_for_status(ctx, job_arn: str, terminal_statuses, timeout_s: float = 300.0):
    bedrock = ctx.client("bedrock")
    deadline = time.monotonic() + timeout_s
    last_status = None
    while time.monotonic() < deadline:
        resp = bedrock.get_evaluation_job(jobIdentifier=job_arn)
        last_status = resp["status"]
        if last_status in terminal_statuses:
            return resp
        time.sleep(2)
    raise AssertionError(f"job never reached {terminal_statuses} within {timeout_s}s, last saw {last_status!r}")


def _wait_for_deletion(ctx, job_arn: str, timeout_s: float = 120.0):
    from botocore.exceptions import ClientError

    bedrock = ctx.client("bedrock")
    deadline = time.monotonic() + timeout_s
    last_status = None
    while time.monotonic() < deadline:
        try:
            resp = bedrock.get_evaluation_job(jobIdentifier=job_arn)
        except ClientError as e:
            if e.response["Error"]["Code"] == "ResourceNotFoundException":
                return
            raise
        last_status = resp["status"]
        if last_status == "Deleted":
            return
        time.sleep(5.0)
    raise AssertionError(f"job never confirmed deleted within {timeout_s}s, last saw {last_status!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
