"""sagemaker-model-creation-s3-modeldata-missing-object-negative."""
from __future__ import annotations

import json
import os
import tarfile
import tempfile
import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "sagemaker-model-creation-s3-modeldata-missing-object-negative"
GROUP = "permission-boundary"
SERVICES = ["s3", "sagemaker"]


@tags("axis:rejection", "cap:c3", "cap:c4", "concern:e2e", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateModel with a ModelDataUrl object that was never written is refused at once with
    ValidationException and the exact message and registers no model, while the same request with a
    real artifact succeeds and its endpoint reaches InService."""
    s3 = ctx.client("s3")
    iam = ctx.client("iam")
    sm = ctx.client("sagemaker")

    bucket = _create_bucket(ctx, s3, "artifacts")
    good_key = "model/xgboost-model.tar.gz"
    s3.put_object(Bucket=bucket, Key=good_key, Body=_build_xgboost_model_tarball())
    missing_key = "model/does-not-exist.tar.gz"  # never written

    role_arn = _create_execution_role(
        ctx,
        iam,
        "hosting",
        [
            {"Effect": "Allow", "Action": ["s3:GetObject"], "Resource": f"arn:aws:s3:::{bucket}/*"},
            {"Effect": "Allow", "Action": ["s3:ListBucket"], "Resource": f"arn:aws:s3:::{bucket}"},
            {
                "Effect": "Allow",
                "Action": ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"],
                "Resource": "*",
            },
        ],
    )
    image_uri = _xgboost_image_uri(ctx.region)

    # ---- positive control: real artifact, produced-and-written in this same run ----
    model_good = ctx.unique_name("sim2real-sm-model-good-")
    _call_with_role_retry(
        lambda: sm.create_model(
            ModelName=model_good,
            PrimaryContainer={"Image": image_uri, "ModelDataUrl": f"s3://{bucket}/{good_key}"},
            ExecutionRoleArn=role_arn,
            Tags=[{"Key": "sim2real", "Value": CHECK}],
        )
    )
    ctx.on_cleanup(lambda: sm.delete_model(ModelName=model_good))

    epc_name = ctx.unique_name("sim2real-sm-epc-good-")
    sm.create_endpoint_config(
        EndpointConfigName=epc_name,
        ProductionVariants=[
            {"VariantName": "AllTraffic", "ModelName": model_good, "InstanceType": "ml.m5.large", "InitialInstanceCount": 1}
        ],
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: sm.delete_endpoint_config(EndpointConfigName=epc_name))

    ep_name = ctx.unique_name("sim2real-sm-ep-good-")
    _call_with_role_retry(
        lambda: sm.create_endpoint(EndpointName=ep_name, EndpointConfigName=epc_name, Tags=[{"Key": "sim2real", "Value": CHECK}])
    )
    ctx.on_cleanup(lambda: sm.delete_endpoint(EndpointName=ep_name))

    good_desc = _wait_for_endpoint_terminal(sm, ep_name, timeout_s=900)
    assert good_desc["EndpointStatus"] == "InService", (
        f"positive control (real artifact, same role/config shape) must reach InService, got "
        f"{good_desc['EndpointStatus']!r} reason={good_desc.get('FailureReason')}"
    )

    # ---- negative: ModelDataUrl points at an S3 object that was never written ----
    # AWS rejects this synchronously at CreateModel ("ValidationException: Could not find model
    # data at s3://<bucket>/<key>"), never at deploy time.
    model_missing = ctx.unique_name("sim2real-sm-model-missing-")
    deadline = time.monotonic() + 90.0
    code: str | None = None
    message: str = ""
    while True:
        try:
            sm.create_model(
                ModelName=model_missing,
                PrimaryContainer={"Image": image_uri, "ModelDataUrl": f"s3://{bucket}/{missing_key}"},
                ExecutionRoleArn=role_arn,
                Tags=[{"Key": "sim2real", "Value": CHECK}],
            )
        except ClientError as e:
            code = e.response["Error"]["Code"]
            message = e.response["Error"].get("Message", "")
            role_propagation = "not authorized" in message.lower() or "assumerole" in message.lower()
            if role_propagation and time.monotonic() < deadline:
                time.sleep(5.0)
                continue
            break
        else:
            ctx.on_cleanup(lambda: sm.delete_model(ModelName=model_missing))
            raise AssertionError(
                "CreateModel with a ModelDataUrl pointing at a nonexistent S3 object was "
                "expected to be rejected synchronously, but it was accepted"
            )

    assert code == "ValidationException", (
        f"CreateModel with a ModelDataUrl pointing at a nonexistent S3 object was expected to be "
        f"rejected synchronously with ValidationException, got {code!r}: {message!r}"
    )
    want = f"Could not find model data at s3://{bucket}/{missing_key}."
    assert message == want, (
        f"ValidationException message should describe the missing model data: expected {want!r}, "
        f"got {message!r}"
    )

    # the rejected model was never registered - an independent read must not find it
    try:
        sm.describe_model(ModelName=model_missing)
        raise AssertionError("DescribeModel unexpectedly found the model that CreateModel rejected")
    except ClientError as err:
        describe_code = err.response["Error"]["Code"]
        assert describe_code == "ValidationException", (
            f"CreateModel was rejected but DescribeModel returned {describe_code!r} instead of "
            "confirming the model was never registered"
        )
        describe_message = err.response["Error"].get("Message")
        assert describe_message == f'Could not find model "{model_missing}".', (
            f"DescribeModel of the rejected model said {describe_message!r} instead of "
            "confirming the model was never registered"
        )


# AWS's own published per-region ECR registry accounts for the SageMaker built-in XGBoost
# image - the container lives in a region-pinned
# registry account, so the account id must match ctx.region.
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


def _xgboost_image_uri(region: str) -> str:
    account = _XGB_REGISTRY_ACCOUNTS.get(region)
    if account is None:
        raise AssertionError(
            f"no known SageMaker built-in XGBoost ECR registry account hardcoded for region "
            f"{region!r} (AWS retired the per-region Docker-registry-path doc table; only a "
            "subset of regions is mapped here) - add the account id to close this gap"
        )
    return f"{account}.dkr.ecr.{region}.amazonaws.com/sagemaker-xgboost:1.7-1"


def _build_xgboost_model_tarball() -> bytes:
    import numpy as np
    import xgboost as xgb

    rng = np.random.default_rng(1234)
    x = rng.uniform(0, 1, size=(64, 4))
    y = x[:, 0] * 2.0 + x[:, 1] - x[:, 2] * 0.5 + 1.0
    dtrain = xgb.DMatrix(x, label=y)
    booster = xgb.train({"objective": "reg:squarederror", "max_depth": 3, "eta": 0.3}, dtrain, num_boost_round=10)

    with tempfile.TemporaryDirectory() as tmp:
        model_path = os.path.join(tmp, "xgboost-model")
        booster.save_model(model_path)
        tar_path = os.path.join(tmp, "model.tar.gz")
        with tarfile.open(tar_path, "w:gz") as tar:
            tar.add(model_path, arcname="xgboost-model")
        with open(tar_path, "rb") as f:
            return f.read()


def _create_bucket(ctx, s3, suffix: str) -> str:
    bucket = ctx.unique_name(f"sim2real-sm-{suffix}-")
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region})
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [{"Key": "sim2real", "Value": CHECK}]})
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(s3, bucket))
    return bucket


def _empty_and_delete_bucket(s3, bucket: str) -> None:
    try:
        resp = s3.list_objects_v2(Bucket=bucket)
        while True:
            contents = resp.get("Contents", [])
            if contents:
                s3.delete_objects(Bucket=bucket, Delete={"Objects": [{"Key": o["Key"]} for o in contents]})
            if not resp.get("IsTruncated"):
                break
            resp = s3.list_objects_v2(Bucket=bucket, ContinuationToken=resp["NextContinuationToken"])
    finally:
        s3.delete_bucket(Bucket=bucket)


def _create_execution_role(ctx, iam, name_suffix: str, statements: list[dict[str, Any]]) -> str:
    role_name = ctx.unique_name(f"sim2real-sm-role-{name_suffix}-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": "sagemaker.amazonaws.com"}, "Action": "sts:AssumeRole"}],
    }
    iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    role_arn = iam.get_role(RoleName=role_name)["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))

    policy_name = f"{role_name}-policy"
    iam.put_role_policy(
        RoleName=role_name, PolicyName=policy_name, PolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": statements})
    )
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name))
    # IAM role/policy propagation is not a fixed delay: every call that assumes this role
    # (create_model, create_endpoint) goes through _call_with_role_retry below instead.
    return role_arn


def _call_with_role_retry(fn, timeout_s: float = 90.0, interval_s: float = 5.0):
    deadline = time.monotonic() + timeout_s
    last_exc: Exception | None = None
    while time.monotonic() < deadline:
        try:
            return fn()
        except ClientError as e:
            msg = str(e)
            if "not authorized" in msg or "AssumeRole" in msg:
                last_exc = e
                time.sleep(interval_s)
                continue
            raise
    raise last_exc  # type: ignore[misc]


def _wait_for_endpoint_terminal(sm, endpoint_name: str, timeout_s: float = 900.0, interval_s: float = 20.0) -> dict[str, Any]:
    deadline = time.monotonic() + timeout_s
    desc: dict[str, Any] = {}
    while time.monotonic() < deadline:
        desc = sm.describe_endpoint(EndpointName=endpoint_name)
        if desc["EndpointStatus"] in ("InService", "Failed"):
            return desc
        time.sleep(interval_s)
    return sm.describe_endpoint(EndpointName=endpoint_name)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
