"""sagemaker-autopilot-job-writes-candidates-to-s3."""
from __future__ import annotations

import json
import random
import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "sagemaker-autopilot-job-writes-candidates-to-s3"
GROUP = "artifact-output"
SERVICES = ["s3", "sagemaker"]


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "concern:e2e", "dp:api", "plane:data")
def run(ctx: Any) -> None:
    """A real Autopilot (AutoML v2) job writes its candidate-definition notebook and
    data-exploration artifacts to the configured S3 OutputDataConfig path -- proof the
    job actually ran the candidate-generation pipeline rather than faking Completed.
    """
    s3 = ctx.client("s3")
    sm = ctx.client("sagemaker")

    bucket = _create_bucket(ctx)
    role = _create_role(ctx, bucket)

    data_key = "automl-input/train.csv"
    s3.put_object(Bucket=bucket, Key=data_key, Body=_tabular_csv().encode("utf-8"))

    job_name = ctx.unique_name("sim2real-sm-automl-")
    _create_auto_ml_job_with_role_propagation_retry(
        ctx,
        sm,
        AutoMLJobName=job_name,
        AutoMLJobInputDataConfig=[{
            "ChannelType": "training",
            "ContentType": "text/csv;header=present",
            "DataSource": {"S3DataSource": {
                "S3DataType": "S3Prefix",
                "S3Uri": f"s3://{bucket}/{data_key}",
            }},
        }],
        OutputDataConfig={"S3OutputPath": f"s3://{bucket}/automl-output/"},
        AutoMLProblemTypeConfig={"TabularJobConfig": {
            "TargetAttributeName": "target",
            "Mode": "ENSEMBLING",
            "ProblemType": "BinaryClassification",
            "CompletionCriteria": {"MaxCandidates": 3, "MaxAutoMLJobRuntimeInSeconds": 1800},
        }},
        AutoMLJobObjective={"MetricName": "F1"},
        RoleArn=role["arn"],
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: _stop_auto_ml_job_unless_finished(sm, job_name))

    desc = _poll_until(
        lambda: sm.describe_auto_ml_job_v2(AutoMLJobName=job_name),
        lambda d: d["AutoMLJobStatus"] in ("Completed", "Failed", "Stopped"),
        timeout_s=_budget_s(ctx, 2700),
        interval_s=2,
        ctx=ctx,
    )
    assert desc["AutoMLJobStatus"] == "Completed", desc.get("FailureReason")

    artifacts = desc["AutoMLJobArtifacts"]
    candidate_uri = artifacts["CandidateDefinitionNotebookLocation"]
    exploration_uri = artifacts["DataExplorationNotebookLocation"]
    _assert_s3_object_exists(s3, candidate_uri)
    _assert_s3_object_exists(s3, exploration_uri)

    # Best candidate's inference container must also reference a real, existing S3 model.
    best = desc["BestCandidate"]
    model_data_urls = [
        c["ModelDataUrl"] for c in best["InferenceContainers"] if "ModelDataUrl" in c
    ]
    assert model_data_urls, f"best candidate {best.get('CandidateName')!r} has no InferenceContainers with a ModelDataUrl: {best['InferenceContainers']}"
    for url in model_data_urls:
        _assert_s3_object_exists(s3, url)


def _tabular_csv(n_rows: int = 600) -> str:
    rng = random.Random(4242)
    lines = ["target,feature1,feature2,feature3"]
    for i in range(n_rows):
        label = i % 2
        f1 = rng.uniform(0, 1) + label * 2.0
        f2 = rng.uniform(0, 1) + label * 2.0
        f3 = rng.uniform(0, 1) - label * 1.0
        lines.append(f"{label},{f1:.4f},{f2:.4f},{f3:.4f}")
    return "\n".join(lines) + "\n"


def _assert_s3_object_exists(s3, s3_uri: str) -> None:
    assert s3_uri.startswith("s3://"), s3_uri
    without_scheme = s3_uri[len("s3://"):]
    bucket, _, key = without_scheme.partition("/")
    head = s3.head_object(Bucket=bucket, Key=key)
    assert head["ContentLength"] > 0, f"{s3_uri} exists but is empty (ContentLength={head['ContentLength']})"


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _create_auto_ml_job_with_role_propagation_retry(ctx: Any, sm: Any, **kwargs: Any) -> None:
    """A just-created IAM role is not reliably assumable by SageMaker yet -- retry the
    CreateAutoMLJobV2 call on the specific propagation-delay rejection instead of guessing
    a fixed sleep, and re-raise immediately on anything else."""
    budget_s = _budget_s(ctx, 90)
    deadline = time.monotonic() + budget_s
    last: ClientError | None = None
    while time.monotonic() < deadline:
        try:
            sm.create_auto_ml_job_v2(**kwargs)
            return
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code", "")
            message = exc.response.get("Error", {}).get("Message", "").lower()
            if code != "ValidationException" or "assume" not in message:
                raise
            last = exc
            time.sleep(2)
    if _budget_spent(ctx):
        raise TimeoutError("role to become assumable: the run budget ended first; not graded")
    raise AssertionError(f"role never became assumable within {budget_s:.0f}s: {last}")


def _stop_auto_ml_job_unless_finished(sm: Any, job_name: str) -> None:
    """Stop the job; a job that already reached a terminal state needs no stop."""
    try:
        sm.stop_auto_ml_job(AutoMLJobName=job_name)
    except ClientError as exc:
        err = exc.response.get("Error", {})
        if err.get("Code") != "ValidationException" or "already reached a terminal state" not in err.get("Message", ""):
            raise


def _poll_until(probe, predicate, timeout_s: float = 600.0, interval_s: float = 15.0, ctx=None):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    if ctx is not None and _budget_spent(ctx):
        raise TimeoutError("condition: the run budget ended first; not graded")
    raise AssertionError(f"condition not met within {timeout_s:.0f}s; last value={last}")


def _create_bucket(ctx: Any) -> str:
    s3 = ctx.client("s3")
    name = ctx.unique_name("sim2real-sm-s3-").lower()
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=name)
    else:
        s3.create_bucket(Bucket=name, CreateBucketConfiguration={"LocationConstraint": ctx.region})
    s3.put_bucket_tagging(Bucket=name, Tagging={"TagSet": [{"Key": "sim2real-check", "Value": CHECK}]})

    def _cleanup() -> None:
        contents = s3.list_objects_v2(Bucket=name).get("Contents", [])
        if contents:
            s3.delete_objects(Bucket=name, Delete={"Objects": [{"Key": o["Key"]} for o in contents]})
        s3.delete_bucket(Bucket=name)

    ctx.on_cleanup(_cleanup)
    return name


def _create_role(ctx: Any, bucket: str) -> dict[str, str]:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-sm-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"Service": "sagemaker.amazonaws.com"},
            "Action": "sts:AssumeRole",
        }],
    }
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )
    role_arn = role["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    policy_arn = "arn:aws:iam::aws:policy/AmazonSageMakerFullAccess"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=policy_arn))
    # AmazonSageMakerFullAccess's own S3 grant is scoped to bucket names matching
    # *sagemaker*/*aws-glue* (real AWS: "Could not upload to S3 bucket ... Please ensure
    # that the role ... has s3:PutObject permissions on the bucket" against a
    # non-matching bucket name) -- an inline policy scoped to the exact bucket this job
    # reads/writes is required regardless of naming.
    bucket_policy_name = "sim2real-automl-bucket-access"
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName=bucket_policy_name,
        PolicyDocument=json.dumps({
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Action": ["s3:GetObject", "s3:PutObject", "s3:ListBucket"],
                "Resource": [f"arn:aws:s3:::{bucket}", f"arn:aws:s3:::{bucket}/*"],
            }],
        }),
    )
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=bucket_policy_name))
    return {"arn": role_arn, "name": role_name}


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
