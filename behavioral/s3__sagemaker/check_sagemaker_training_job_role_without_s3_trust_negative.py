"""sagemaker-training-job-role-without-s3-trust-negative."""
from __future__ import annotations

import json
import random
import time
from typing import Any

from behavioral_harness import tags

CHECK = "sagemaker-training-job-role-without-s3-trust-negative"
GROUP = "permission-boundary"
SERVICES = ["s3", "sagemaker"]


@tags("axis:rejection", "cap:c3", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateTrainingJob synchronously rejects a role whose trust policy does not name
    sagemaker.amazonaws.com and creates no job, while an identical request with a
    properly-trusted role is accepted."""

    s3 = ctx.client("s3")
    sm = ctx.client("sagemaker")

    bucket = _create_bucket(ctx)
    s3.put_object(Bucket=bucket, Key="train/train.csv", Body=_xgb_csv(60, seed=7).encode("utf-8"))
    image = _resolve_algo_image(ctx, "xgboost", "1")

    def _job_kwargs(name: str, role_arn: str) -> dict:
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
            HyperParameters={"num_round": "10", "objective": "binary:logistic"},
            Tags=[{"Key": "sim2real", "Value": CHECK}],
        )

    # Broken: trust policy names ec2.amazonaws.com instead of sagemaker.amazonaws.com.
    role_bad = _create_role_with_trust(ctx, "ec2.amazonaws.com", [f"arn:aws:s3:::{bucket}"])
    job_bad = _name(ctx, "trust-bad")

    def _create_bad() -> None:
        sm.create_training_job(**_job_kwargs(job_bad, role_bad))

    unassumable = (
        "ValidationException",
        f"Could not assume role {role_bad}. Please ensure that the role exists and allows "
        f"principal 'sagemaker.amazonaws.com' to assume the role.",
    )
    error = _client_error(_create_bad)
    assert error == unassumable, f"expected the untrusted role to be refused as unassumable, got {error}"

    listing = sm.list_training_jobs(NameContains=job_bad)
    names = [j["TrainingJobName"] for j in listing.get("TrainingJobSummaries", [])]
    assert job_bad not in names, (
        f"no training job resource should exist after a rejected CreateTrainingJob, "
        f"but ListTrainingJobs(NameContains={job_bad!r}) returned {names}"
    )

    # Positive control: same request, properly-trusted role -- accepted.
    role_ok = _create_execution_role(ctx, [f"arn:aws:s3:::{bucket}"])
    job_ok = _name(ctx, "trust-ok")
    _create_training_job_with_retry(sm, **_job_kwargs(job_ok, role_ok))
    ctx.on_cleanup(lambda: _best_effort_stop(sm, job_ok))

    desc = sm.describe_training_job(TrainingJobName=job_ok)
    assert desc["TrainingJobStatus"] in ("InProgress", "Completed", "Stopping", "Stopped"), (
        f"expected the properly-trusted request to be accepted, got {desc['TrainingJobStatus']}"
    )


# ===== helpers =====
_PREFIX = "sim2real-smk-"

# AWS-published built-in-algorithm ECR registry account per region (a fixed API constant,
# not this account's own id or a resource pinned to a region).
_BUILTIN_ALGO_ACCOUNTS = {
    "us-east-1": "811284229777",
    "us-east-2": "825641698319",
    "us-west-1": "632365934929",
    "us-west-2": "433757028032",
    "ap-northeast-1": "501404015308",
    "ap-northeast-2": "306986355934",
    "ap-south-1": "991648021394",
    "ap-southeast-1": "475088953585",
    "ap-southeast-2": "544295431143",
    "ca-central-1": "469771592824",
    "eu-central-1": "813361260812",
    "eu-north-1": "669576153137",
    "eu-west-1": "685385470294",
    "eu-west-2": "644912444149",
    "eu-west-3": "749696950732",
    "sa-east-1": "855470959533",
}


def _name(ctx: Any, kind: str) -> str:
    return ctx.unique_name(f"{_PREFIX}{kind}-")


def _xgb_csv(n: int, seed: int = 0) -> str:
    rnd = random.Random(seed)
    lines = []
    for i in range(n):
        label = i % 2
        f1 = rnd.uniform(0, 1) + label * 2
        f2 = rnd.uniform(0, 1) + label * 2
        lines.append(f"{label},{f1:.4f},{f2:.4f}")
    return "\n".join(lines) + "\n"


def _client_error(fn) -> tuple[str, str]:
    """The (code, message) of the ClientError fn raises; raises AssertionError when fn succeeds."""
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError("the call succeeded, but AWS refuses it")


def _create_bucket(ctx: Any) -> str:
    s3 = ctx.client("s3")
    name = _name(ctx, "bkt")
    kwargs: dict[str, Any] = {"Bucket": name}
    if ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kwargs)
    s3.put_bucket_tagging(Bucket=name, Tagging={"TagSet": [{"Key": "sim2real", "Value": CHECK}]})

    def _cleanup() -> None:
        objs = s3.list_objects_v2(Bucket=name).get("Contents", [])
        for o in objs:
            s3.delete_object(Bucket=name, Key=o["Key"])
        s3.delete_bucket(Bucket=name)

    ctx.on_cleanup(_cleanup)
    return name


def _create_role_with_trust(ctx: Any, trust_service: str, bucket_arns: list[str]) -> str:
    iam = ctx.client("iam")
    role_name = _name(ctx, "role")
    trust = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": trust_service}, "Action": "sts:AssumeRole"}],
    }
    iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: _delete_role(ctx, role_name))

    resources: list[str] = []
    for arn in bucket_arns:
        resources.append(arn)
        resources.append(arn + "/*")
    statements = [
        {
            "Effect": "Allow",
            "Action": ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents", "logs:DescribeLogStreams"],
            "Resource": "*",
        },
        {"Effect": "Allow", "Action": ["s3:GetObject", "s3:PutObject", "s3:ListBucket"], "Resource": resources},
    ]
    policy_name = _name(ctx, "policy")
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName=policy_name,
        PolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": statements}),
    )
    return iam.get_role(RoleName=role_name)["Role"]["Arn"]


def _create_execution_role(ctx: Any, bucket_arns: list[str]) -> str:
    return _create_role_with_trust(ctx, "sagemaker.amazonaws.com", bucket_arns)


def _delete_role(ctx: Any, role_name: str) -> None:
    iam = ctx.client("iam")
    for pol in iam.list_role_policies(RoleName=role_name).get("PolicyNames", []):
        iam.delete_role_policy(RoleName=role_name, PolicyName=pol)
    iam.delete_role(RoleName=role_name)


def _resolve_algo_image(ctx: Any, algo: str, tag: str) -> str:
    account = _BUILTIN_ALGO_ACCOUNTS.get(ctx.region)
    if not account:
        raise AssertionError(f"no known built-in-algorithm ECR account for region {ctx.region}")
    return f"{account}.dkr.ecr.{ctx.region}.amazonaws.com/{algo}:{tag}"


def _create_training_job_with_retry(sm, timeout_s: float = 120, poll_s: float = 10, **kwargs) -> dict:
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return sm.create_training_job(**kwargs)
        except ClientError as e:
            code = e.response["Error"]["Code"]
            msg = e.response["Error"].get("Message", "").lower()
            role_propagation = "trust" in msg or "assume role" in msg or "not authorized" in msg
            if code == "ValidationException" and role_propagation and time.monotonic() < deadline:
                time.sleep(poll_s)
                continue
            raise


def _best_effort_stop(sm, job_name: str) -> None:
    from botocore.exceptions import ClientError

    try:
        sm.stop_training_job(TrainingJobName=job_name)
    except ClientError as exc:
        # A job that is not InProgress refuses the stop with ValidationException; anything else fails.
        if exc.response["Error"]["Code"] != "ValidationException" or sm.describe_training_job(TrainingJobName=job_name)["TrainingJobStatus"] == "InProgress":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
