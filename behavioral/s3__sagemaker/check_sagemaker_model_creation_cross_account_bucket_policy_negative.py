"""sagemaker-model-creation-cross-account-bucket-policy-negative."""

from __future__ import annotations

import json
import os
import tarfile
import tempfile
import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "sagemaker-model-creation-cross-account-bucket-policy-negative"
GROUP = "permission-boundary"
SERVICES = ["s3", "sagemaker"]


@tags(
    "axis:rejection",
    "cap:c3",
    "cap:c4",
    "cap:c7",
    "concern:data-plane",
    "concern:e2e",
    "concern:negative-classes",
    "dp:api",
    "plane:data",
)
def run(ctx) -> None:
    """CreateModel cannot load artifacts from a bucket whose policy denies the execution role, whatever
    the role's identity policy allows (the Deny-wins outcome of a cross-account bucket that never
    grants the role), while a sibling model on an open bucket with the same role deploys.
    """
    s3 = ctx.client("s3")
    iam = ctx.client("iam")
    sm = ctx.client("sagemaker")

    denied_bucket = _create_bucket(ctx, s3, "denied")
    open_bucket = _create_bucket(ctx, s3, "open")
    key = "model/xgboost-model.tar.gz"
    tarball = _build_xgboost_model_tarball()
    s3.put_object(Bucket=denied_bucket, Key=key, Body=tarball)
    s3.put_object(Bucket=open_bucket, Key=key, Body=tarball)

    role_arn = _create_execution_role(
        ctx,
        iam,
        "hosting",
        [
            {
                "Effect": "Allow",
                "Action": ["s3:GetObject"],
                "Resource": [
                    f"arn:aws:s3:::{denied_bucket}/*",
                    f"arn:aws:s3:::{open_bucket}/*",
                ],
            },
            {
                "Effect": "Allow",
                "Action": [
                    "logs:CreateLogGroup",
                    "logs:CreateLogStream",
                    "logs:PutLogEvents",
                ],
                "Resource": "*",
            },
        ],
    )

    # The bucket policy explicitly denies GetObject to this specific role, overriding the
    # role's own identity-based Allow above - the same outcome a foreign-account bucket
    # policy produces when it simply never grants the role access.
    # Wrapped in the role-propagation retry: a bucket policy naming a JUST-CREATED role ARN as a
    # principal is rejected with "MalformedPolicy: Invalid principal in policy" until IAM has
    # propagated that role (on real AWS, the first call after CreateRole).
    _denied_bucket_policy = json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Deny",
                    "Principal": {"AWS": role_arn},
                    "Action": "s3:GetObject",
                    "Resource": f"arn:aws:s3:::{denied_bucket}/*",
                }
            ],
        }
    )
    _call_with_role_retry(
        lambda: s3.put_bucket_policy(Bucket=denied_bucket, Policy=_denied_bucket_policy)
    )

    image_uri = _xgboost_image_uri(ctx.region)
    endpoints = {}
    # POSITIVE CONTROL FIRST, deliberately. CreateModel validates artifact access SYNCHRONOUSLY on
    # real AWS (for the denied bucket it answers "ValidationException: Could
    # not access model data at s3://.../model/xgboost-model.tar.gz. Please ensure that the role
    # ... exists and that it has permission ..."), and that message is indistinguishable from an
    # IAM-propagation failure. Creating the OPEN model first with the SAME role settles which one
    # it is: if the open model is accepted, the role is usable and the denied model's refusal can
    # only be the bucket policy.
    for label, bucket in (("open", open_bucket), ("denied", denied_bucket)):
        model_name = ctx.unique_name(f"sim2real-sm-model-{label}-")
        if label == "denied":
            try:
                sm.create_model(
                    ModelName=model_name,
                    PrimaryContainer={
                        "Image": image_uri,
                        "ModelDataUrl": f"s3://{bucket}/{key}",
                    },
                    ExecutionRoleArn=role_arn,
                    Tags=[{"Key": "sim2real-check", "Value": CHECK}],
                )
            except ClientError as exc:
                err = exc.response["Error"]
                assert err.get("Code") == "ValidationException", (
                    "CreateModel on a bucket-policy-denied artifact should be refused with a "
                    f"ValidationException, got {err.get('Code')!r}: {err.get('Message')!r}"
                )
                want = (
                    f"Could not access model data at s3://{bucket}/{key}. Please ensure that the "
                    f"role \"{role_arn}\" exists and that its trust relationship policy allows the "
                    "action \"sts:AssumeRole\" for the service principal \"sagemaker.amazonaws.com\". "
                ) + (
                    "Also ensure that the role has \"s3:GetObject\" permissions and that the object "
                    f"is located in {ctx.region}. If your Model uses multiple models or uncompressed "
                    "models, please ensure that the role has \"s3:ListBucket\" permission."
                )
                assert err.get("Message") == want, (
                    "CreateModel on a bucket-policy-denied artifact should name the inaccessible "
                    f"model data: expected {want!r}, got {err.get('Message')!r}"
                )
                continue
            ctx.on_cleanup(lambda m=model_name: sm.delete_model(ModelName=m))
            raise AssertionError(
                "CreateModel accepted an artifact the bucket policy explicitly denies to the "
                "execution role; real AWS refuses it synchronously (Deny wins over the role's "
                "own identity-based Allow)"
            )
        _call_with_role_retry(
            lambda m=model_name, b=bucket: sm.create_model(
                ModelName=m,
                PrimaryContainer={
                    "Image": image_uri,
                    "ModelDataUrl": f"s3://{b}/{key}",
                },
                ExecutionRoleArn=role_arn,
                Tags=[{"Key": "sim2real-check", "Value": CHECK}],
            )
        )
        ctx.on_cleanup(lambda m=model_name: sm.delete_model(ModelName=m))

        epc_name = ctx.unique_name(f"sim2real-sm-epc-{label}-")
        sm.create_endpoint_config(
            EndpointConfigName=epc_name,
            ProductionVariants=[
                {
                    "VariantName": "AllTraffic",
                    "ModelName": model_name,
                    "InstanceType": "ml.m5.large",
                    "InitialInstanceCount": 1,
                }
            ],
            Tags=[{"Key": "sim2real-check", "Value": CHECK}],
        )
        ctx.on_cleanup(
            lambda n=epc_name: sm.delete_endpoint_config(EndpointConfigName=n)
        )

        ep_name = ctx.unique_name(f"sim2real-sm-ep-{label}-")
        _call_with_role_retry(
            lambda n=ep_name, c=epc_name: sm.create_endpoint(
                EndpointName=n,
                EndpointConfigName=c,
                Tags=[{"Key": "sim2real-check", "Value": CHECK}],
            )
        )
        ctx.on_cleanup(lambda n=ep_name: sm.delete_endpoint(EndpointName=n))
        endpoints[label] = ep_name

    assert "denied" not in endpoints, (
        "the denied model must never have reached endpoint creation: CreateModel is where real AWS "
        "refuses it"
    )
    results = _wait_for_endpoints_terminal(sm, list(endpoints.values()), timeout_s=900)

    open_desc = results[endpoints["open"]]

    assert open_desc["EndpointStatus"] == "InService", (
        f"positive control (same role, unrestricted bucket) must reach InService, got "
        f"{open_desc['EndpointStatus']!r} reason={open_desc.get('FailureReason')}"
    )


# ===== helpers (self-contained) =====

# Region-pinned by construction: each value is the AWS-owned ECR registry account that
# hosts the SageMaker built-in XGBoost image *in that specific region* (a fixed mapping,
# not an account setting), so the literal region keys are the resource identity, not a
# convenience default.
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
    # Tag 3.0-5, not 1.7-1: the artifact this check uploads is written by the runner's
    # xgboost (3.x, which saves UBJSON by default), and a 1.7 container cannot load a model
    # saved by a newer major version. 3.0-5 is a real built-in version (sagemaker 2.257.6
    # image_uri_config/xgboost.json lists 3.0-5 with the same per-region registry map).
    return f"{account}.dkr.ecr.{region}.amazonaws.com/sagemaker-xgboost:3.0-5"


def _build_xgboost_model_tarball() -> bytes:
    import numpy as np
    import xgboost as xgb

    rng = np.random.default_rng(1234)
    x = rng.uniform(0, 1, size=(64, 4))
    y = x[:, 0] * 2.0 + x[:, 1] - x[:, 2] * 0.5 + 1.0
    dtrain = xgb.DMatrix(x, label=y)
    booster = xgb.train(
        {"objective": "reg:squarederror", "max_depth": 3, "eta": 0.3},
        dtrain,
        num_boost_round=10,
    )

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
        s3.create_bucket(
            Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region}
        )
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(s3, bucket))
    s3.put_bucket_tagging(
        Bucket=bucket, Tagging={"TagSet": [{"Key": "sim2real-check", "Value": CHECK}]}
    )
    return bucket


def _empty_and_delete_bucket(s3, bucket: str) -> None:
    try:
        resp = s3.list_objects_v2(Bucket=bucket)
        while True:
            contents = resp.get("Contents", [])
            if contents:
                s3.delete_objects(
                    Bucket=bucket,
                    Delete={"Objects": [{"Key": o["Key"]} for o in contents]},
                )
            if not resp.get("IsTruncated"):
                break
            resp = s3.list_objects_v2(
                Bucket=bucket, ContinuationToken=resp["NextContinuationToken"]
            )
    finally:
        s3.delete_bucket(Bucket=bucket)


def _create_execution_role(
    ctx, iam, name_suffix: str, statements: list[dict[str, Any]]
) -> str:
    role_name = ctx.unique_name(f"sim2real-sm-role-{name_suffix}-")
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
    iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )
    role_arn = iam.get_role(RoleName=role_name)["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))

    policy_name = f"{role_name}-policy"
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName=policy_name,
        PolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": statements}),
    )
    ctx.on_cleanup(
        lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name)
    )
    return role_arn


def _call_with_role_retry(fn, timeout_s: float = 90.0, interval_s: float = 5.0):
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    last_exc: Exception | None = None
    while time.monotonic() < deadline:
        try:
            return fn()
        except ClientError as e:
            msg = str(e)
            # "Invalid principal in policy" (MalformedPolicy) is the same eventual-consistency
            # class: S3 rejects a policy naming an IAM role that has not propagated yet.
            if "not authorized" in msg or "AssumeRole" in msg or "Invalid principal" in msg:
                last_exc = e
                time.sleep(interval_s)
                continue
            raise
    raise last_exc  # type: ignore[misc]


def _wait_for_endpoints_terminal(
    sm, endpoint_names: list[str], timeout_s: float = 900.0, interval_s: float = 20.0
) -> dict[str, Any]:
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


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
