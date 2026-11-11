"""iam-role-missing-sagemaker-trust-blocks-training-job-negative."""
from __future__ import annotations

import json
import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "iam-role-missing-sagemaker-trust-blocks-training-job-negative"
GROUP = "permission-boundary"
SERVICES = ["s3", "sagemaker"]

_XGBOOST_ACCOUNTS = {
    "us-east-1": "811284229777",
    "us-east-2": "825641698319",
    "us-west-1": "632365934929",
    "us-west-2": "433757028032",
    "eu-west-1": "685385470294",
    "eu-central-1": "813361260812",
    "ap-northeast-1": "501404015308",
    "ap-southeast-1": "475088953585",
    "ap-southeast-2": "544295431143",
    "ca-central-1": "469771592824",
}


@tags("axis:rejection", "cap:c3", "cap:c4", "concern:data-plane", "concern:e2e", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """A training job passed a role that does not trust sagemaker.amazonaws.com is rejected and
    writes no output, while an identically-permissioned role that trusts SageMaker (positive
    control) trains to completion."""
    image_uri = _resolve_algo_image(ctx)
    s3 = ctx.client("s3")
    iam = ctx.client("iam")
    sm = ctx.client("sagemaker")

    bucket = ctx.unique_name("sim2real-sm-trust-")
    _create_bucket(ctx, s3, bucket)
    _upload_training_csv(s3, bucket, "train/train.csv")

    s3_statements = [{
        "Effect": "Allow",
        "Action": ["s3:GetObject", "s3:PutObject", "s3:ListBucket"],
        "Resource": [f"arn:aws:s3:::{bucket}", f"arn:aws:s3:::{bucket}/*"],
    }]

    trusted_role_arn = _create_role(
        ctx, iam, ctx.unique_name("sim2real-sm-trusted-"), "sagemaker.amazonaws.com", s3_statements
    )
    untrusted_role_arn = _create_role(
        ctx, iam, ctx.unique_name("sim2real-sm-untrusted-"), "ec2.amazonaws.com", s3_statements
    )
    bad_job = ctx.unique_name("sim2real-sm-bad-")
    try:
        _launch_training_job(sm, bad_job, image_uri, untrusted_role_arn, bucket, "output-bad/")
    except ClientError as e:
        code = e.response["Error"]["Code"]
        msg = e.response["Error"].get("Message", "")
        expected_msg = (
            f"Could not assume role {untrusted_role_arn}. Please ensure that the role exists and "
            "allows principal 'sagemaker.amazonaws.com' to assume the role."
        )
        assert code == "ValidationException" and msg == expected_msg, (
            "a training job using a role that does not trust sagemaker.amazonaws.com was "
            f"expected to be rejected synchronously with ValidationException/'could not "
            f"assume role', got {code}: {msg}"
        )
    else:
        raise AssertionError(
            "CreateTrainingJob with a role that does not trust sagemaker.amazonaws.com "
            "was expected to be rejected synchronously, but it was accepted"
        )
    ctx.on_cleanup(lambda: _best_effort_stop_training(sm, bad_job))
    bad_listing = s3.list_objects_v2(Bucket=bucket, Prefix=f"output-bad/{bad_job}/")
    assert "Contents" not in bad_listing, (
        f"untrusted-role job wrote output despite never being assumable: {bad_listing.get('Contents')}"
    )

    good_job = ctx.unique_name("sim2real-sm-good-")
    _launch_training_job(sm, good_job, image_uri, trusted_role_arn, bucket, "output-good/")
    ctx.on_cleanup(lambda: _best_effort_stop_training(sm, good_job))

    good_desc = _wait_training_terminal(sm, good_job, timeout_s=1200)
    assert good_desc["TrainingJobStatus"] == "Completed", (
        f"positive control (trusted role, same permissions) failed to complete: "
        f"{good_desc.get('FailureReason')}"
    )
    good_listing = s3.list_objects_v2(Bucket=bucket, Prefix=f"output-good/{good_job}/output/")
    good_keys = [o["Key"] for o in good_listing.get("Contents", [])]
    assert any(k.endswith("model.tar.gz") for k in good_keys), (
        f"positive control completed but produced no model artifact: {good_keys}"
    )


# ===== helpers =====

def _resolve_algo_image(ctx: Any, algo: str = "xgboost", tag: str = "1") -> str:
    try:
        from sagemaker import image_uris  # type: ignore

        return image_uris.retrieve(algo, ctx.region, version=tag)
    except Exception:
        pass

    account = _XGBOOST_ACCOUNTS.get(ctx.region)
    if account is None:
        raise AssertionError(
            f"no known SageMaker built-in XGBoost algorithm registry account mapped for "
            f"region {ctx.region!r} in this check - add it to close the gap"
        )
    return f"{account}.dkr.ecr.{ctx.region}.amazonaws.com/{algo}:{tag}"


def _create_bucket(ctx: Any, s3: Any, bucket: str) -> None:
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(
            Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region}
        )
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [{"Key": "sim2real", "Value": "sm-trust-negative"}]})
    ctx.on_cleanup(lambda: _delete_bucket(s3, bucket))


def _delete_bucket(s3: Any, bucket: str) -> None:
    try:
        while True:
            resp = s3.list_objects_v2(Bucket=bucket)
            contents = resp.get("Contents", [])
            if not contents:
                break
            s3.delete_objects(
                Bucket=bucket, Delete={"Objects": [{"Key": o["Key"]} for o in contents]}
            )
            if not resp.get("IsTruncated"):
                break
        s3.delete_bucket(Bucket=bucket)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchBucket":
            raise


def _upload_training_csv(s3: Any, bucket: str, key: str, n_rows: int = 60) -> None:
    import random

    rng = random.Random(42)
    lines = []
    for _ in range(n_rows):
        f1 = rng.uniform(0, 10)
        f2 = rng.uniform(0, 10)
        label = 2.0 * f1 + 3.0 * f2 + rng.uniform(-0.5, 0.5)
        lines.append(f"{label:.4f},{f1:.4f},{f2:.4f}")
    s3.put_object(Bucket=bucket, Key=key, Body="\n".join(lines).encode("utf-8"))


def _create_role(ctx: Any, iam: Any, role_name: str, trust_service: str, s3_statements: list) -> str:
    trust = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"Service": trust_service},
            "Action": "sts:AssumeRole",
        }],
    }
    resp = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": "sm-trust-negative"}],
    )
    role_arn = resp["Role"]["Arn"]
    ctx.on_cleanup(lambda: _delete_role(iam, role_name))
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName="s3-access",
        PolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": s3_statements}),
    )
    return role_arn


def _delete_role(iam: Any, role_name: str) -> None:
    try:
        for pol in iam.list_role_policies(RoleName=role_name).get("PolicyNames", []):
            iam.delete_role_policy(RoleName=role_name, PolicyName=pol)
        iam.delete_role(RoleName=role_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _launch_training_job(
    sm: Any, job_name: str, image_uri: str, role_arn: str, bucket: str, output_prefix: str
) -> None:
    _create_training_job_with_retry(
        sm,
        TrainingJobName=job_name,
        AlgorithmSpecification={"TrainingImage": image_uri, "TrainingInputMode": "File"},
        RoleArn=role_arn,
        InputDataConfig=[{
            "ChannelName": "train",
            "DataSource": {"S3DataSource": {
                "S3DataType": "S3Prefix",
                "S3Uri": f"s3://{bucket}/train/",
                "S3DataDistributionType": "FullyReplicated",
            }},
            "ContentType": "text/csv",
        }],
        OutputDataConfig={"S3OutputPath": f"s3://{bucket}/{output_prefix}"},
        ResourceConfig={"InstanceType": "ml.m5.large", "InstanceCount": 1, "VolumeSizeInGB": 5},
        StoppingCondition={"MaxRuntimeInSeconds": 900},
        HyperParameters={"objective": "reg:linear", "num_round": "5"},
        Tags=[{"Key": "sim2real", "Value": "sm-trust-negative"}],
    )


def _create_training_job_with_retry(sm: Any, timeout_s: float = 60, poll_s: float = 10, **kwargs) -> dict:
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return sm.create_training_job(**kwargs)
        except ClientError as e:
            code = e.response["Error"]["Code"]
            msg = e.response["Error"].get("Message", "").lower()
            # A brand-new role's trust policy can take a few seconds to propagate; retry
            # ONLY while the deadline has not elapsed, so a genuinely-untrusted role (the
            # negative case in this file) still surfaces its ValidationException promptly
            # once the short retry budget is exhausted.
            role_propagation = "assume role" in msg or "not authorized" in msg
            if code == "ValidationException" and role_propagation and time.monotonic() < deadline:
                time.sleep(poll_s)
                continue
            raise


def _wait_training_terminal(sm: Any, job_name: str, timeout_s: float = 1200.0, interval_s: float = 15.0) -> dict:
    deadline = time.monotonic() + timeout_s
    desc: dict = {}
    while time.monotonic() < deadline:
        desc = sm.describe_training_job(TrainingJobName=job_name)
        if desc["TrainingJobStatus"] in ("Completed", "Failed", "Stopped"):
            return desc
        time.sleep(interval_s)
    raise AssertionError(f"training job {job_name} never reached a terminal state: {desc}")


def _best_effort_stop_training(sm: Any, job_name: str) -> None:
    try:
        status = sm.describe_training_job(TrainingJobName=job_name)["TrainingJobStatus"]
    except ClientError as exc:
        # The rejected job was never created.
        if "not found" not in exc.response["Error"].get("Message", "").lower():
            raise
        return
    if status != "InProgress":
        return
    try:
        sm.stop_training_job(TrainingJobName=job_name)
    except ClientError as err:
        # A job that has left InProgress refuses the stop with ValidationException; anything else fails.
        if err.response["Error"]["Code"] != "ValidationException" or sm.describe_training_job(TrainingJobName=job_name)["TrainingJobStatus"] == "InProgress":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
