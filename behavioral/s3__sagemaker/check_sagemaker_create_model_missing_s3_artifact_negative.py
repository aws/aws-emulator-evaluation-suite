"""sagemaker-create-model-missing-s3-artifact-negative."""
from __future__ import annotations

import json
import time
from typing import Any

from behavioral_harness import tags

CHECK = "sagemaker-create-model-missing-s3-artifact-negative"
GROUP = "permission-boundary"
SERVICES = ["s3", "sagemaker"]

# Built-in XGBoost images live in a per-region AWS-owned ECR registry whose account id differs
# by region; other regions raise rather than guess an account id.
_XGBOOST_IMAGES = {
    "us-east-1": "683313688378.dkr.ecr.us-east-1.amazonaws.com/sagemaker-xgboost:1.7-1",
    "us-west-2": "246618743249.dkr.ecr.us-west-2.amazonaws.com/sagemaker-xgboost:1.7-1",
}


@tags("axis:rejection", "cap:c3", "cap:c4", "concern:e2e", "concern:negative-classes", "plane:control")
def run(ctx: Any) -> None:
    """CreateModel with a ModelDataUrl key that was never written fails synchronously with the exact
    ValidationException and creates no model; a present object succeeds, and writing the missing
    key makes the identical CreateModel succeed.
    """
    image = _XGBOOST_IMAGES.get(ctx.region)
    if image is None:
        raise AssertionError(
            f"no verified built-in XGBoost image mapping maintained for region {ctx.region}; "
            "add an entry to _XGBOOST_IMAGES to close this gap for other regions."
        )

    s3 = ctx.client("s3")
    sm = ctx.client("sagemaker")

    bucket = _create_bucket(ctx)
    role = _create_role(ctx, bucket)

    # CreateModel checks only that the object exists, not that it is a valid archive.
    good_key = "artifacts/model.tar.gz"
    s3.put_object(Bucket=bucket, Key=good_key, Body=b"not a real archive -- CreateModel only checks presence")
    good_model_name = ctx.unique_name("sim2real-sm-model-good-")
    good_url = f"s3://{bucket}/{good_key}"
    _create_model_with_retry(
        sm,
        ModelName=good_model_name,
        PrimaryContainer={"Image": image, "ModelDataUrl": good_url},
        ExecutionRoleArn=role["arn"],
        Tags=[{"Key": "sim2real", "Value": "missing-s3-artifact"}],
    )
    ctx.on_cleanup(lambda: sm.delete_model(ModelName=good_model_name))
    described_good = sm.describe_model(ModelName=good_model_name)
    assert described_good["PrimaryContainer"]["ModelDataUrl"] == good_url, (
        f"positive control: DescribeModel must echo the ModelDataUrl it was created with: "
        f"{described_good['PrimaryContainer']}"
    )
    good_names = [m["ModelName"] for m in sm.list_models(NameContains=good_model_name)["Models"]]
    assert good_model_name in good_names, (
        f"positive control: {good_model_name!r} must be visible in ListModels: {good_names}"
    )

    bad_key = "never-written/model.tar.gz"
    missing_url = f"s3://{bucket}/{bad_key}"
    assert _client_error(lambda: s3.head_object(Bucket=bucket, Key=bad_key))["Code"] == "404", (
        "the artifact under test must really be absent before CreateModel is asked about it"
    )

    bad_model_name = ctx.unique_name("sim2real-sm-model-bad-")
    err = _client_error(lambda: sm.create_model(
        ModelName=bad_model_name,
        PrimaryContainer={"Image": image, "ModelDataUrl": missing_url},
        ExecutionRoleArn=role["arn"],
        Tags=[{"Key": "sim2real", "Value": "missing-s3-artifact"}],
    ))
    assert err.get("Code") == "ValidationException", (
        f"CreateModel against a never-written S3 key must be rejected with ValidationException, "
        f"not turned into some other outcome: {err}"
    )
    expected_message = f"Could not find model data at {missing_url}."
    assert err.get("Message") == expected_message, (
        f"the rejection must name the exact missing model data URL: {err}"
    )

    bad_names = [m["ModelName"] for m in sm.list_models(NameContains=bad_model_name)["Models"]]
    assert bad_model_name not in bad_names, (
        f"a rejected CreateModel must not leave a model behind: {bad_names}"
    )
    describe_err = _client_error(lambda: sm.describe_model(ModelName=bad_model_name))
    assert describe_err.get("Code") == "ValidationException", (
        f"DescribeModel on a never-created model must fail the same way ListModels agrees it does "
        f"not exist: {describe_err}"
    )
    assert describe_err.get("Message") == f'Could not find model "{bad_model_name}".', describe_err

    s3.put_object(Bucket=bucket, Key=bad_key, Body=b"now the object exists at the exact key that was missing")
    sm.create_model(
        ModelName=bad_model_name,
        PrimaryContainer={"Image": image, "ModelDataUrl": missing_url},
        ExecutionRoleArn=role["arn"],
        Tags=[{"Key": "sim2real", "Value": "missing-s3-artifact"}],
    )
    ctx.on_cleanup(lambda: sm.delete_model(ModelName=bad_model_name))
    described_bad = sm.describe_model(ModelName=bad_model_name)
    assert described_bad["PrimaryContainer"]["ModelDataUrl"] == missing_url, (
        f"once the object exists at the exact key that was missing, the identical CreateModel "
        f"call must succeed and echo that URL: {described_bad['PrimaryContainer']}"
    )


def _client_error(fn) -> dict:
    """Call fn(); return its botocore Error dict, or raise if fn() unexpectedly succeeds."""
    from botocore.exceptions import ClientError
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {})
    raise AssertionError(f"expected fn() to raise a ClientError, but it SUCCEEDED and returned {result!r}")


def _create_model_with_retry(sm, *, timeout_s: float = 60.0, **kwargs) -> None:
    """Call create_model, retrying while the just-created execution role propagates in IAM.

    An unpropagated permission surfaces as "Could not access model data", not only "assume role".
    """
    from botocore.exceptions import ClientError
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            sm.create_model(**kwargs)
            return
        except ClientError as exc:
            err = exc.response["Error"]
            msg = (err.get("Message") or "").lower()
            if err.get("Code") == "ValidationException" \
                    and ("assume role" in msg or "not authorized" in msg
                         or "could not access model data" in msg) \
                    and time.monotonic() < deadline:
                time.sleep(5)
                continue
            raise


def _create_bucket(ctx: Any) -> str:
    s3 = ctx.client("s3")
    name = ctx.unique_name("sim2real-sm-s3-").lower()
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=name)
    else:
        s3.create_bucket(Bucket=name, CreateBucketConfiguration={"LocationConstraint": ctx.region})
    s3.put_bucket_tagging(
        Bucket=name, Tagging={"TagSet": [{"Key": "sim2real", "Value": "missing-s3-artifact"}]}
    )

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
        Tags=[{"Key": "sim2real", "Value": "missing-s3-artifact"}],
    )
    role_arn = role["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    policy_arn = "arn:aws:iam::aws:policy/AmazonSageMakerFullAccess"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=policy_arn))
    # AmazonSageMakerFullAccess only grants S3 on bucket names containing "sagemaker".
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName="bucket-scoped",
        PolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": [{
            "Effect": "Allow",
            "Action": ["s3:GetObject", "s3:PutObject", "s3:ListBucket"],
            "Resource": [f"arn:aws:s3:::{bucket}", f"arn:aws:s3:::{bucket}/*"],
        }]}),
    )
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName="bucket-scoped"))
    return {"arn": role_arn, "name": role_name}


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
