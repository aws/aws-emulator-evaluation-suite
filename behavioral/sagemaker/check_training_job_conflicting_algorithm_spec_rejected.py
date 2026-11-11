"""training-job-conflicting-algorithm-spec-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "training-job-conflicting-algorithm-spec-rejected"
GROUP = "server-side"
SERVICES = ["sagemaker"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateTrainingJob synchronously rejects an AlgorithmSpecification setting both AlgorithmName
    and TrainingImage, leaving no job; without AlgorithmName the same call starts InProgress and
    runs to Completed."""
    image_uri = _xgboost_image_uri(ctx)
    bucket = _create_bucket(ctx)
    role_arn = _create_sagemaker_role(ctx, bucket)
    train_uri = _upload_csv(ctx, bucket, "train/train.csv")

    sm = ctx.client("sagemaker")

    bad_job_name = ctx.unique_name("sagemaker-sim2real-badspec-")
    common_kwargs = dict(
        RoleArn=role_arn,
        HyperParameters={"objective": "binary:logistic", "num_round": "2"},
        InputDataConfig=[
            {
                "ChannelName": "train",
                "ContentType": "text/csv",
                "DataSource": {
                    "S3DataSource": {
                        "S3DataType": "S3Prefix",
                        "S3Uri": train_uri,
                        "S3DataDistributionType": "FullyReplicated",
                    }
                },
            }
        ],
        OutputDataConfig={"S3OutputPath": f"s3://{bucket}/output/"},
        ResourceConfig={"InstanceType": "ml.m5.large", "InstanceCount": 1, "VolumeSizeInGB": 5},
        StoppingCondition={"MaxRuntimeInSeconds": 900},
    )

    code, message = _error_code_and_message(
        lambda: sm.create_training_job(
            TrainingJobName=bad_job_name,
            AlgorithmSpecification={
                "TrainingImage": image_uri,
                "AlgorithmName": "some-nonexistent-algorithm-name",
                "TrainingInputMode": "File",
            },
            **common_kwargs,
        )
    )
    assert code == "ValidationException", (
        f"expected ValidationException for a spec with both AlgorithmName and "
        f"TrainingImage, got {code}"
    )
    # Real AWS resolves AlgorithmName before it weighs the conflict, so the refusal names
    # the algorithm it could not find.
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    assert message == (
        f"Algorithm arn:aws:sagemaker:{ctx.region}:{account_id}:algorithm/"
        "some-nonexistent-algorithm-name does not exist."
    ), f"unexpected conflicting-spec rejection message: {message!r}"

    # effect absent: the rejected call must never have created a resource
    # SageMaker's DescribeTrainingJob answers an unknown job name with ValidationException, not
    # the ResourceNotFound its own Smithy model declares.
    not_found_code, not_found_message = _error_code_and_message(
        lambda: sm.describe_training_job(TrainingJobName=bad_job_name)
    )
    assert not_found_code == "ValidationException", (
        f"expected the rejected create to have left no training job behind, "
        f"got describe_training_job error code {not_found_code!r} message {not_found_message!r}"
    )
    assert not_found_message == "Requested resource not found.", (
        f"unexpected DescribeTrainingJob not-found message: {not_found_message!r}"
    )

    # positive control: same call, minus the conflicting AlgorithmName, is accepted
    good_job_name = ctx.unique_name("sagemaker-sim2real-goodspec-")
    ctx.on_cleanup(lambda: _best_effort_delete_training_job(ctx, good_job_name))
    _create_training_job_with_role_retry(
        sm,
        TrainingJobName=good_job_name,
        AlgorithmSpecification={"TrainingImage": image_uri, "TrainingInputMode": "File"},
        **common_kwargs,
    )
    accepted = sm.describe_training_job(TrainingJobName=good_job_name)
    # A job that already ran to Completed before this describe was accepted and started too.
    assert accepted["TrainingJobStatus"] in ("InProgress", "Completed"), (
        f"expected the corrected AlgorithmSpecification to be accepted and start "
        f"(InProgress, or already Completed), got {accepted['TrainingJobStatus']}"
    )
    # The managed state machine runs to a terminal status; the accepted job completes.
    settled = _poll_training_job_terminal(sm, good_job_name, timeout_s=_budget_s(ctx, 1200), ctx=ctx)
    assert settled["TrainingJobStatus"] == "Completed", (
        f"expected the corrected AlgorithmSpecification to be accepted and run to "
        f"Completed, got {settled['TrainingJobStatus']} ({settled.get('FailureReason')!r})"
    )


def _error_code_and_message(fn):
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


def _poll_training_job_terminal(sm, job_name: str, timeout_s: float, ctx=None) -> dict:
    deadline = time.monotonic() + timeout_s
    while True:
        described = sm.describe_training_job(TrainingJobName=job_name)
        if described["TrainingJobStatus"] in ("Completed", "Failed", "Stopped"):
            return described
        if time.monotonic() >= deadline:
            if ctx is not None and _budget_spent(ctx):
                raise TimeoutError(f"training job {job_name} to reach a terminal status: the run budget ended first; not graded")
            raise AssertionError(
                f"training job {job_name} stayed {described['TrainingJobStatus']} past {timeout_s}s"
            )
        time.sleep(2)


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


#: SageMaker's built-in XGBoost image lives in a distinct ECR registry account per region;
#: these values are transcribed from the sagemaker SDK's ``image_uri_config/xgboost.json``.
_XGB_REGISTRY_ACCOUNTS = {
    "us-east-1": "683313688378",
    "us-east-2": "257758044811",
    "us-west-1": "746614075791",
    "us-west-2": "246618743249",
    "ap-northeast-1": "354813040037",
    "ap-northeast-2": "366743142698",
    "ap-south-1": "720646828776",
    "ap-southeast-1": "121021644041",
    "ap-southeast-2": "783357654285",
    "ca-central-1": "341280168497",
    "eu-central-1": "492215442770",
    "eu-north-1": "662702820516",
    "eu-west-1": "141502667606",
    "eu-west-2": "764974769150",
    "eu-west-3": "659782779980",
    "sa-east-1": "737474898029",
}


def _xgboost_image_uri(ctx) -> str:
    region = ctx.region
    account = _XGB_REGISTRY_ACCOUNTS.get(region)
    if account is None:
        raise AssertionError(
            f"no SageMaker built-in XGBoost ECR registry account mapped for region {region!r} "
            "- add it from the SDK's image_uri_config/xgboost.json to close this gap"
        )
    return f"{account}.dkr.ecr.{region}.amazonaws.com/sagemaker-xgboost:1.7-1"


def _create_bucket(ctx) -> str:
    s3 = ctx.client("s3")
    name = ctx.unique_name("sagemaker-sim2real-")
    # us-east-1 is S3's CreateBucket special case: it rejects an explicit LocationConstraint.
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=name)
    else:
        s3.create_bucket(
            Bucket=name, CreateBucketConfiguration={"LocationConstraint": ctx.region}
        )
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(ctx, name))
    return name


def _empty_and_delete_bucket(ctx, name: str) -> None:
    s3 = ctx.client("s3")
    try:
        resp = s3.list_objects_v2(Bucket=name)
        for obj in resp.get("Contents", []):
            s3.delete_object(Bucket=name, Key=obj["Key"])
        s3.delete_bucket(Bucket=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchBucket":
            raise RuntimeError(f"s3 bucket {name} was not deleted: {exc!r}") from exc


def _upload_csv(ctx, bucket: str, key: str) -> str:
    s3 = ctx.client("s3")
    rows = ["0,1.0,2.0", "1,2.0,1.0", "0,1.5,2.5", "1,3.0,0.5"]
    s3.put_object(Bucket=bucket, Key=key, Body="\n".join(rows).encode("utf-8"))
    return f"s3://{bucket}/{key}"


def _create_sagemaker_role(ctx, bucket: str) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sagemaker-sim2real-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "sagemaker.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust))
    ctx.on_cleanup(lambda: _delete_sagemaker_role(ctx, role_name))
    iam.attach_role_policy(
        RoleName=role_name,
        PolicyArn="arn:aws:iam::aws:policy/AmazonSageMakerFullAccess",
    )
    inline_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": ["s3:GetObject", "s3:PutObject", "s3:ListBucket"],
                "Resource": [f"arn:aws:s3:::{bucket}", f"arn:aws:s3:::{bucket}/*"],
            }
        ],
    }
    iam.put_role_policy(
        RoleName=role_name, PolicyName="s3-access", PolicyDocument=json.dumps(inline_policy)
    )
    return iam.get_role(RoleName=role_name)["Role"]["Arn"]


def _delete_sagemaker_role(ctx, role_name: str) -> None:
    iam = ctx.client("iam")
    failures = []
    for step in (
        lambda: iam.delete_role_policy(RoleName=role_name, PolicyName="s3-access"),
        lambda: iam.detach_role_policy(
            RoleName=role_name, PolicyArn="arn:aws:iam::aws:policy/AmazonSageMakerFullAccess"
        ),
        lambda: iam.delete_role(RoleName=role_name),
    ):
        try:
            step()
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                failures.append(exc)
    if failures:
        raise RuntimeError(f"iam role {role_name} was not deleted: {failures!r}")


def _create_training_job_with_role_retry(sm, **kwargs):
    deadline = time.monotonic() + 90
    last_exc = None
    while time.monotonic() < deadline:
        try:
            return sm.create_training_job(**kwargs)
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code in ("AccessDeniedException", "ValidationException") and "assume" in str(exc).lower():
                last_exc = exc
                time.sleep(2)
                continue
            raise
    raise last_exc


def _training_job_gone(exc: ClientError) -> bool:
    """DescribeTrainingJob answers an unknown job with ValidationException "Requested resource not found."."""
    err = exc.response["Error"]
    return err["Code"] == "ResourceNotFound" or (
        err["Code"] == "ValidationException" and "not found" in err.get("Message", "").lower()
    )


def _best_effort_delete_training_job(ctx, job_name: str) -> None:
    sm = ctx.client("sagemaker")
    try:
        status = sm.describe_training_job(TrainingJobName=job_name)["TrainingJobStatus"]
        if status in ("InProgress", "Stopping"):
            sm.stop_training_job(TrainingJobName=job_name)
            for _ in range(30):
                status = sm.describe_training_job(TrainingJobName=job_name)["TrainingJobStatus"]
                if status not in ("InProgress", "Stopping"):
                    break
                time.sleep(2)
            else:
                raise RuntimeError(f"training job {job_name} was not deleted: still {status!r} after stop")
        sm.delete_training_job(TrainingJobName=job_name)
    except ClientError as exc:
        if not _training_job_gone(exc):
            raise RuntimeError(f"training job {job_name} was not deleted: {exc!r}") from exc


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
