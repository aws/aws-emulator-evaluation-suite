"""presigned-mlflow-app-url-not-found-for-missing-app."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "presigned-mlflow-app-url-not-found-for-missing-app"
GROUP = "error-semantics"
SERVICES = ["sagemaker"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreatePresignedMlflowAppUrl for a nonexistent MLflow App Arn is rejected with
    ValidationException, while a live Created app yields a URL, so the rejection is specific
    to the missing app rather than a blanket denial."""
    sm = ctx.client("sagemaker")
    sts = ctx.client("sts")
    s3 = ctx.client("s3")
    account_id = sts.get_caller_identity()["Account"]

    role_arn = _create_mlflow_role(ctx)
    bucket = _create_bucket(ctx, s3)

    app_name = ctx.unique_name("sim2real-mlapp-")
    arn = _create_mlflow_app_with_retry(
        sm, name=app_name, artifact_store_uri=f"s3://{bucket}/mlflow-apps/{app_name}/", role_arn=role_arn
    )
    ctx.on_cleanup(lambda: _delete_mlflow_app(sm, arn))

    _wait_for_created(sm, arn, timeout_s=1800, interval_s=20)

    # Positive control: a real, live MLflow App yields a usable presigned URL, so the account
    # and role are otherwise healthy for this operation.
    fresh = sm.create_presigned_mlflow_app_url(Arn=arn)
    assert fresh.get("AuthorizedUrl"), f"expected a presigned URL for a live MLflow App, got {fresh}"

    missing_arn = f"arn:aws:sagemaker:{ctx.region}:{account_id}:mlflow-app/{ctx.unique_name('sim2real-mlapp-')}"
    code, message = _error_code_and_message(lambda: sm.create_presigned_mlflow_app_url(Arn=missing_arn))
    # CreatePresignedMlflowAppUrl declares ResourceNotFound, but empirically a nonexistent
    # MLflow App Arn surfaces as ValidationException ("Resource does not exist") instead.
    assert code == "ValidationException", message
    assert message == "Resource does not exist", message


def _error_code_and_message(fn):
    try:
        fn()
    except ClientError as e:
        err = e.response["Error"]
        return err["Code"], err.get("Message")
    raise AssertionError("expected a rejection, but CreatePresignedMlflowAppUrl SUCCEEDED for a missing app")


def _create_bucket(ctx, s3) -> str:
    bucket = ctx.unique_name("sim2real-mlapp-")
    if ctx.region == "us-east-1":  # S3's own quirk: us-east-1 rejects a LocationConstraint.
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region})
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(s3, bucket))
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [{"Key": "sim2real-check", "Value": CHECK}]})
    return bucket


def _empty_and_delete_bucket(s3, bucket: str) -> None:
    paginator = s3.get_paginator("list_object_versions")
    for page in paginator.paginate(Bucket=bucket):
        objects = [{"Key": v["Key"], "VersionId": v["VersionId"]} for v in page.get("Versions", [])]
        objects += [{"Key": m["Key"], "VersionId": m["VersionId"]} for m in page.get("DeleteMarkers", [])]
        if objects:
            failed = s3.delete_objects(Bucket=bucket, Delete={"Objects": objects}).get("Errors")
            if failed:
                raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
    s3.delete_bucket(Bucket=bucket)


def _create_mlflow_role(ctx) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-mlapp-role-")
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "sagemaker.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    policy_arn = "arn:aws:iam::aws:policy/AmazonS3FullAccess"
    resp = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_policy),
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )
    arn = resp["Role"]["Arn"]
    iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)

    def _cleanup():
        try:
            iam.detach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise
        iam.delete_role(RoleName=role_name)

    ctx.on_cleanup(_cleanup)

    for _ in range(15):
        try:
            iam.get_role(RoleName=role_name)
            break
        except ClientError:
            time.sleep(2)
    return arn


def _create_mlflow_app_with_retry(sm, *, name: str, artifact_store_uri: str, role_arn: str, timeout_s: float = 120, interval_s: float = 5):
    """A just-created role is not always immediately assumable by SageMaker; retry only on the
    AssumeRole-trust ValidationException, never unconditionally."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return sm.create_mlflow_app(
                Name=name,
                ArtifactStoreUri=artifact_store_uri,
                RoleArn=role_arn,
                Tags=[{"Key": "sim2real-check", "Value": CHECK}],
            )["Arn"]
        except ClientError as exc:
            err = exc.response["Error"]
            if err.get("Code") == "ValidationException" and "AssumeRole" in err.get("Message", "") and time.monotonic() < deadline:
                time.sleep(interval_s)
                continue
            raise


def _wait_for_created(sm, arn: str, *, timeout_s: float, interval_s: float) -> None:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        status = sm.describe_mlflow_app(Arn=arn)["Status"]
        if status == "Created":
            return
        if status in ("CreateFailed", "UpdateFailed", "DeleteFailed"):
            raise AssertionError(f"MLflow App entered {status} while waiting for Created")
        time.sleep(interval_s)
    raise AssertionError(f"MLflow App did not reach Created within {timeout_s}s")


def _delete_mlflow_app(sm, arn: str) -> None:
    try:
        sm.delete_mlflow_app(Arn=arn)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFound":
            raise
        return
    # A deleted MLflow App keeps describing with Status "Deleted" before it reports ResourceNotFound;
    # both mean the delete finished. The bound stays inside the suite's teardown budget.
    deadline = time.monotonic() + 600
    while time.monotonic() < deadline:
        try:
            status = sm.describe_mlflow_app(Arn=arn)["Status"]
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "ResourceNotFound":
                return
            raise
        if status == "Deleted":
            return
        if status == "DeleteFailed":
            raise AssertionError(f"MLflow App {arn} entered DeleteFailed")
        time.sleep(15)
    raise AssertionError(f"MLflow App {arn} did not finish deleting within 600s of delete")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
