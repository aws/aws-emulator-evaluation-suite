"""sagemaker-endpoint-data-capture-missing-s3-write-permission-negative."""
from __future__ import annotations

import json
import os
import tarfile
import tempfile
import time
from typing import Any

from behavioral_harness import tags

CHECK = "sagemaker-endpoint-data-capture-missing-s3-write-permission-negative"
GROUP = "permission-boundary"
SERVICES = ["s3", "sagemaker"]


@tags("axis:negative-delivery", "cap:c3", "cap:c4", "cap:c7", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """An endpoint whose role lacks s3:PutObject on the DataCaptureConfig destination still answers
    inference with 200 but writes no capture objects, while a sibling endpoint whose role has the grant
    writes capture objects for the same invocations."""
    s3 = ctx.client("s3")
    iam = ctx.client("iam")
    sm = ctx.client("sagemaker")
    smrt = ctx.client("sagemaker-runtime")

    artifact_bucket = _create_bucket(ctx, s3, "artifacts")
    key = "model/xgboost-model.tar.gz"
    s3.put_object(Bucket=artifact_bucket, Key=key, Body=_build_xgboost_model_tarball())
    image_uri = _xgboost_image_uri(ctx.region)

    capture_bucket = _create_bucket(ctx, s3, "capture")
    capture_prefix = "capture"

    # Negative: role can read the model artifact but has NO grant at all on the capture bucket.
    role_no_write = _create_execution_role(
        ctx,
        iam,
        "nowrite",
        [
            {"Effect": "Allow", "Action": ["s3:GetObject"], "Resource": f"arn:aws:s3:::{artifact_bucket}/{key}"},
            {"Effect": "Allow", "Action": ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"], "Resource": "*"},
        ],
    )
    # Positive control: identical role shape, but also granted s3:PutObject on the capture prefix.
    role_with_write = _create_execution_role(
        ctx,
        iam,
        "withwrite",
        [
            {"Effect": "Allow", "Action": ["s3:GetObject"], "Resource": f"arn:aws:s3:::{artifact_bucket}/{key}"},
            {"Effect": "Allow", "Action": ["s3:PutObject"], "Resource": f"arn:aws:s3:::{capture_bucket}/{capture_prefix}/*"},
            {"Effect": "Allow", "Action": ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"], "Resource": "*"},
        ],
    )

    endpoints = {}
    for label, role_arn in (("nowrite", role_no_write), ("withwrite", role_with_write)):
        model_name = ctx.unique_name(f"sim2real-sm-model-{label}-")
        _call_with_role_retry(
            lambda m=model_name, r=role_arn: sm.create_model(
                ModelName=m,
                PrimaryContainer={"Image": image_uri, "ModelDataUrl": f"s3://{artifact_bucket}/{key}"},
                ExecutionRoleArn=r,
                Tags=[{"Key": "sim2real", "Value": CHECK}],
            )
        )
        ctx.on_cleanup(lambda m=model_name: sm.delete_model(ModelName=m))

        epc_name = ctx.unique_name(f"sim2real-sm-epc-{label}-")
        sm.create_endpoint_config(
            EndpointConfigName=epc_name,
            ProductionVariants=[
                {"VariantName": "AllTraffic", "ModelName": model_name, "InstanceType": "ml.m5.large", "InitialInstanceCount": 1}
            ],
            DataCaptureConfig={
                "EnableCapture": True,
                "InitialSamplingPercentage": 100,
                "DestinationS3Uri": f"s3://{capture_bucket}/{capture_prefix}/{label}",
                "CaptureOptions": [{"CaptureMode": "Input"}, {"CaptureMode": "Output"}],
            },
            Tags=[{"Key": "sim2real", "Value": CHECK}],
        )
        ctx.on_cleanup(lambda n=epc_name: sm.delete_endpoint_config(EndpointConfigName=n))

        ep_name = ctx.unique_name(f"sim2real-sm-ep-{label}-")
        _call_with_role_retry(
            lambda n=ep_name, c=epc_name: sm.create_endpoint(
                EndpointName=n, EndpointConfigName=c, Tags=[{"Key": "sim2real", "Value": CHECK}]
            )
        )
        ctx.on_cleanup(lambda n=ep_name: sm.delete_endpoint(EndpointName=n))
        endpoints[label] = ep_name

    results = _wait_for_endpoints_terminal(sm, list(endpoints.values()), timeout_s=900)
    for label, ep_name in endpoints.items():
        assert results[ep_name]["EndpointStatus"] == "InService", (
            f"endpoint {label} did not come up (capture permission should not affect hosting): "
            f"{results[ep_name].get('FailureReason')}"
        )

    payload = "0.5,0.5,0.5,0.5\n"
    for _ in range(3):
        resp = smrt.invoke_endpoint(EndpointName=endpoints["nowrite"], ContentType="text/csv", Body=payload)
        assert resp["ResponseMetadata"]["HTTPStatusCode"] == 200, (
            f"inference itself must not fail even though capture cannot write to S3: {resp['ResponseMetadata']}"
        )
    invoke_time = time.monotonic()
    for _ in range(3):
        smrt.invoke_endpoint(EndpointName=endpoints["withwrite"], ContentType="text/csv", Body=payload)

    with_write_objects = _poll_for_objects(s3, capture_bucket, f"{capture_prefix}/withwrite/", timeout_s=240)
    assert with_write_objects, "positive control: capture objects never appeared even though the role has s3:PutObject"
    # Calibrate the absence window off the positive control's own measured delivery latency L (on
    # the same wiring, same run) instead of a guessed constant, so a correct-but-slower target
    # cannot be scored as having blocked.
    positive_latency_s = time.monotonic() - invoke_time
    no_write_timeout_s = max(60.0, 3 * positive_latency_s)

    no_write_objects = _poll_for_objects(s3, capture_bucket, f"{capture_prefix}/nowrite/", timeout_s=no_write_timeout_s)
    assert no_write_objects == [], (
        f"capture objects appeared under the nowrite prefix despite the execution role lacking "
        f"s3:PutObject on the capture bucket: {no_write_objects}"
    )


# AWS-owned ECR registry accounts hosting the built-in XGBoost algorithm image, one per
# region; these are AWS's own fixed, publicly-documented registry accounts, not a
# per-account/adjustable value, so pinning them here is a contract, not a shortcut.
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
    return role_arn


def _call_with_role_retry(fn, timeout_s: float = 90.0, interval_s: float = 5.0):
    """Bounded retry for the window where a just-created IAM role/policy is not yet
    visible to SageMaker's AssumeRole check (eventual consistency, not a fixed delay)."""
    from botocore.exceptions import ClientError

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


def _wait_for_endpoints_terminal(sm, endpoint_names: list[str], timeout_s: float = 900.0, interval_s: float = 20.0) -> dict[str, Any]:
    deadline = time.monotonic() + timeout_s
    pending = set(endpoint_names)
    results: dict[str, Any] = {}
    while pending and time.monotonic() < deadline:
        for name in list(pending):
            desc = sm.describe_endpoint(EndpointName=name)
            if desc["EndpointStatus"] in ("InService", "Failed"):
                results[name] = desc
                pending.discard(name)
        if pending:
            time.sleep(interval_s)
    for name in pending:
        results[name] = sm.describe_endpoint(EndpointName=name)
    return results


def _poll_for_objects(s3, bucket: str, prefix: str, timeout_s: float = 240.0, interval_s: float = 15.0) -> list[str]:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        resp = s3.list_objects_v2(Bucket=bucket, Prefix=prefix)
        keys = [o["Key"] for o in resp.get("Contents", [])]
        if keys:
            return keys
        time.sleep(interval_s)
    return []


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
