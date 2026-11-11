"""sagemaker-execution-role-trust-policy-missing-negative."""
from __future__ import annotations

import json
import random
import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "sagemaker-execution-role-trust-policy-missing-negative"
GROUP = "permission-boundary"
SERVICES = ["s3", "sagemaker"]

# Per-region built-in-algorithm ECR registry account for the sagemaker-xgboost image; the
# registry account is a region-pinned AWS constant, not a config value this check invents.
_XGBOOST_REGISTRY = {
    "us-east-1": "683313688378",
    "us-east-2": "257758044811",
    "us-west-1": "746614075791",
    "us-west-2": "246618743249",
    "eu-west-1": "685385470294",
    "eu-west-2": "644912444149",
    "eu-west-3": "749696950732",
    "eu-central-1": "813361260812",
    "eu-north-1": "669576153137",
    "ap-northeast-1": "354813040037",
    "ap-northeast-2": "366743142698",
    "ap-southeast-1": "121021644041",
    "ap-southeast-2": "783357654285",
    "ap-south-1": "720646828776",
    "ca-central-1": "341280168497",
    "sa-east-1": "855470959533",
}


@tags("axis:rejection", "cap:c3", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateTrainingJob rejects a role trusted only by ec2.amazonaws.com and creates no job, while
    an otherwise identical role that trusts sagemaker.amazonaws.com is accepted and starts."""
    s3 = ctx.client("s3")
    sm = ctx.client("sagemaker")

    bucket = _create_bucket(ctx)
    s3.put_object(Bucket=bucket, Key="train/data.csv", Body=_training_csv_bytes(60))
    image = _builtin_image_uri(ctx, "sagemaker-xgboost", "1.7-1", _XGBOOST_REGISTRY)

    statements = [
        {
            "Effect": "Allow",
            "Action": ["s3:GetObject", "s3:ListBucket"],
            "Resource": [f"arn:aws:s3:::{bucket}", f"arn:aws:s3:::{bucket}/*"],
        },
        {"Effect": "Allow", "Action": ["s3:PutObject"], "Resource": [f"arn:aws:s3:::{bucket}/output/*"]},
        {
            "Effect": "Allow",
            "Action": ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents", "logs:DescribeLogStreams"],
            "Resource": "arn:aws:logs:*:*:*",
        },
    ]

    # Trust policy does NOT include sagemaker.amazonaws.com.
    role_bad = _create_execution_role(ctx, statements=statements, trust_service="ec2.amazonaws.com")
    job_bad = ctx.unique_name("sim2real-sm-trustneg-")

    def _job_kwargs(name: str, role_arn: str) -> dict[str, Any]:
        return dict(
            TrainingJobName=name,
            AlgorithmSpecification={"TrainingImage": image, "TrainingInputMode": "File"},
            RoleArn=role_arn,
            InputDataConfig=[
                {
                    "ChannelName": "train",
                    "DataSource": {
                        "S3DataSource": {
                            "S3DataType": "S3Prefix",
                            "S3Uri": f"s3://{bucket}/train/",
                            "S3DataDistributionType": "FullyReplicated",
                        }
                    },
                    "ContentType": "text/csv",
                    "CompressionType": "None",
                }
            ],
            OutputDataConfig={"S3OutputPath": f"s3://{bucket}/output/"},
            ResourceConfig={"InstanceType": "ml.m5.large", "InstanceCount": 1, "VolumeSizeInGB": 5},
            StoppingCondition={"MaxRuntimeInSeconds": 900},
            HyperParameters={"objective": "reg:squarederror", "num_round": "10"},
            Tags=[{"Key": "sim2real", "Value": "sagemaker-trust-policy-negative"}],
        )

    unassumable = (
        "ValidationException",
        f"Could not assume role {role_bad}. Please ensure that the role exists and allows "
        f"principal 'sagemaker.amazonaws.com' to assume the role.",
    )
    error = _client_error(lambda: ctx.client("sagemaker").create_training_job(**_job_kwargs(job_bad, role_bad)))
    assert error == unassumable, f"expected the untrusted role to be refused as unassumable, got {error}"

    not_found = _client_error(lambda: sm.describe_training_job(TrainingJobName=job_bad))
    assert not_found == ("ValidationException", "Requested resource not found."), (
        f"expected the rejected CreateTrainingJob to never have registered a job, got {not_found}"
    )

    # Positive control: an otherwise identical role that DOES trust sagemaker.amazonaws.com.
    role_good = _create_execution_role(ctx, statements=statements, trust_service="sagemaker.amazonaws.com")
    job_good = ctx.unique_name("sim2real-sm-trustok-")
    ctx.on_cleanup(lambda: _stop_training_job_if_running(ctx, sm, job_good))

    _create_training_job_with_retry(sm, **_job_kwargs(job_good, role_good))
    status = _wait_for_status_not_failed(sm, job_good, timeout_s=90)
    assert status != "Failed", f"positive-control job unexpectedly failed early: {status}"


# ===== helpers =====

def _gone(exc: ClientError) -> bool:
    """The error says the resource does not exist: never created, or already deleted."""
    err = exc.response["Error"]
    msg = err.get("Message", "").lower()
    return err["Code"] in ("ResourceNotFound", "NoSuchEntity", "NoSuchBucket", "RepositoryNotFoundException") or (
        err["Code"] in ("ValidationException", "ValidationError")
        and any(t in msg for t in ("not found", "does not exist", "could not find"))
    )


def _create_bucket(ctx) -> str:
    s3 = ctx.client("s3")
    name = ctx.unique_name("sim2real-sm-s3-")
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=name)
    else:
        s3.create_bucket(Bucket=name, CreateBucketConfiguration={"LocationConstraint": ctx.region})
    s3.put_bucket_tagging(Bucket=name, Tagging={"TagSet": [{"Key": "sim2real", "Value": "sagemaker-trust-policy-negative"}]})

    def _cleanup() -> None:
        resp = s3.list_objects_v2(Bucket=name)
        keys = [{"Key": o["Key"]} for o in resp.get("Contents", [])]
        if keys:
            s3.delete_objects(Bucket=name, Delete={"Objects": keys})
        s3.delete_bucket(Bucket=name)

    ctx.on_cleanup(_cleanup)
    return name


def _training_csv_bytes(n_rows: int, seed: int = 1234) -> bytes:
    rnd = random.Random(seed)
    lines = []
    for _ in range(n_rows):
        f1, f2, f3 = rnd.uniform(0, 10), rnd.uniform(0, 10), rnd.uniform(0, 10)
        label = 2.0 * f1 - 1.5 * f2 + 0.5 * f3 + rnd.uniform(-0.1, 0.1)
        lines.append(f"{label:.4f},{f1:.4f},{f2:.4f},{f3:.4f}")
    return ("\n".join(lines) + "\n").encode("utf-8")


def _create_execution_role(ctx, *, statements: list[dict[str, Any]], trust_service: str) -> str:
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-sm-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": trust_service}, "Action": "sts:AssumeRole"}
        ],
    }
    role = iam.create_role(
        RoleName=name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": "sagemaker-trust-policy-negative"}],
    )["Role"]
    policy_name = f"{name}-policy"
    iam.put_role_policy(
        RoleName=name,
        PolicyName=policy_name,
        PolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": statements}),
    )

    def _cleanup() -> None:
        try:
            iam.delete_role_policy(RoleName=name, PolicyName=policy_name)
        except ClientError as exc:
            if not _gone(exc):
                raise
        try:
            iam.delete_role(RoleName=name)
        except ClientError as exc:
            if not _gone(exc):
                raise

    ctx.on_cleanup(_cleanup)
    return role["Arn"]


def _builtin_image_uri(ctx, repo: str, tag: str, registry: dict[str, str]) -> str:
    account = registry.get(ctx.region)
    if account is None:
        raise AssertionError(f"no known {repo} built-in-algorithm registry account for region {ctx.region}")
    return f"{account}.dkr.ecr.{ctx.region}.amazonaws.com/{repo}:{tag}"


def _client_error(fn) -> tuple[str, str]:
    """The (code, message) of the ClientError fn raises; raises AssertionError when fn succeeds."""
    try:
        fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError("the call succeeded, but AWS refuses it")


def _create_training_job_with_retry(sm, *, timeout_s: int = 90, **kwargs):
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return sm.create_training_job(**kwargs)
        except ClientError as e:
            code = e.response["Error"]["Code"]
            msg = e.response["Error"].get("Message", "")
            if code == "ValidationException" and "assume role" in msg.lower() and time.monotonic() < deadline:
                time.sleep(5)
                continue
            raise


def _wait_for_status_not_failed(sm, name: str, timeout_s: int = 90, poll_s: int = 10) -> str:
    deadline = time.monotonic() + timeout_s
    status = "InProgress"
    while time.monotonic() < deadline:
        desc = sm.describe_training_job(TrainingJobName=name)
        status = desc["TrainingJobStatus"]
        if status != "InProgress":
            return status
        time.sleep(poll_s)
    return status


def _stop_training_job_if_running(ctx, sm, name: str) -> None:
    try:
        desc = sm.describe_training_job(TrainingJobName=name)
        if desc["TrainingJobStatus"] == "InProgress":
            sm.stop_training_job(TrainingJobName=name)
    except ClientError as exc:
        if not _gone(exc) and (exc.response["Error"]["Code"] != "ValidationException" or sm.describe_training_job(TrainingJobName=name)["TrainingJobStatus"] == "InProgress"):
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
