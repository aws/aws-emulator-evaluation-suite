"""sagemaker-endpoint-data-capture-s3-positive."""

from __future__ import annotations

import base64
import io
import json
import tarfile
import time
from typing import Any

from behavioral_harness import tags

CHECK = "sagemaker-endpoint-data-capture-s3-positive"
GROUP = "endpoint-capture"
SERVICES = ["s3", "sagemaker"]

_MANAGED_TAG = {"Key": "sim2real:managed", "Value": "true"}


@tags(
    "axis:happy-path",
    "cap:c3",
    "cap:c4",
    "concern:data-plane",
    "concern:e2e",
    "dp:api",
    "plane:data",
)
def run(ctx) -> None:
    """An endpoint deployed with DataCaptureConfig actually writes the observed request and
    response payloads as SageMaker's documented JSON-lines capture records to the configured
    S3 destination - not just accepting the config, but producing the artifact."""
    s3 = ctx.client("s3")
    iam = ctx.client("iam")
    sm = ctx.client("sagemaker")
    smrt = ctx.client("sagemaker-runtime")

    artifact_bucket = _create_bucket(ctx, s3, "artifacts")
    key = "model/xgboost-model.tar.gz"
    s3.put_object(Bucket=artifact_bucket, Key=key, Body=_build_xgboost_model_tarball())

    capture_bucket = _create_bucket(ctx, s3, "capture")
    capture_prefix = "capture"

    role_arn = _create_execution_role(
        ctx,
        iam,
        "capture",
        [
            {
                "Effect": "Allow",
                "Action": ["s3:GetObject"],
                "Resource": f"arn:aws:s3:::{artifact_bucket}/{key}",
            },
            {
                "Effect": "Allow",
                "Action": ["s3:PutObject"],
                "Resource": f"arn:aws:s3:::{capture_bucket}/{capture_prefix}/*",
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

    image_uri = _xgboost_image_uri(ctx.region)
    model_name = ctx.unique_name("sim2real-sm-model-")
    _call_with_role_retry(
        lambda: sm.create_model(
            ModelName=model_name,
            PrimaryContainer={
                "Image": image_uri,
                "ModelDataUrl": f"s3://{artifact_bucket}/{key}",
            },
            ExecutionRoleArn=role_arn,
            Tags=[_MANAGED_TAG],
        )
    )
    ctx.on_cleanup(lambda: sm.delete_model(ModelName=model_name))

    endpoint_config_name = ctx.unique_name("sim2real-sm-epc-")
    sm.create_endpoint_config(
        EndpointConfigName=endpoint_config_name,
        ProductionVariants=[
            {
                "VariantName": "AllTraffic",
                "ModelName": model_name,
                "InstanceType": "ml.m5.large",
                "InitialInstanceCount": 1,
            }
        ],
        DataCaptureConfig={
            "EnableCapture": True,
            "InitialSamplingPercentage": 100,
            "DestinationS3Uri": f"s3://{capture_bucket}/{capture_prefix}",
            "CaptureOptions": [{"CaptureMode": "Input"}, {"CaptureMode": "Output"}],
        },
        Tags=[_MANAGED_TAG],
    )
    ctx.on_cleanup(
        lambda: sm.delete_endpoint_config(EndpointConfigName=endpoint_config_name)
    )

    endpoint_name = ctx.unique_name("sim2real-sm-ep-")
    _call_with_role_retry(
        lambda: sm.create_endpoint(
            EndpointName=endpoint_name,
            EndpointConfigName=endpoint_config_name,
            Tags=[_MANAGED_TAG],
        )
    )
    ctx.on_cleanup(lambda: sm.delete_endpoint(EndpointName=endpoint_name))

    desc = _wait_for_endpoint_terminal(sm, endpoint_name, timeout_s=900)
    assert desc["EndpointStatus"] == "InService", (
        f"endpoint did not come up: {desc.get('FailureReason')}"
    )

    payload = "0.5,0.5,0.5,0.5\n"
    invoke_resp = smrt.invoke_endpoint(
        EndpointName=endpoint_name, ContentType="text/csv", Body=payload
    )
    output_data = invoke_resp["Body"].read().decode("utf-8").strip()

    records = _poll_for_capture_records(
        s3, capture_bucket, f"{capture_prefix}/{endpoint_name}/", timeout_s=240
    )
    assert records, (
        "no data-capture records ever landed in the configured S3 destination"
    )
    # A capture record carries each payload with its "encoding": BASE64 unless the content type
    # is listed in CaptureContentTypeHeader, which this config does not set.
    matched = [
        r
        for r in records
        if _captured(r, "endpointInput") == payload
        and _captured(r, "endpointOutput").strip() == output_data
    ]
    assert matched, (
        f"captured records did not contain our request/response payload; saw: {records[:3]}"
    )


# These are AWS's own per-region built-in-algorithm ECR registry account ids (a fixed part of the
# SageMaker contract), not a shortcut for this check's own resource region - ctx.region drives the
# lookup below and the function raises for any region not in this table.
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


def _captured(record: dict, side: str) -> str:
    entry = record.get("captureData", {}).get(side, {})
    data = entry.get("data", "")
    if entry.get("encoding") == "BASE64":
        return base64.b64decode(data).decode("utf-8")
    return data


def _build_xgboost_model_tarball() -> bytes:
    """A one-leaf XGBoost regression model in XGBoost's JSON model format, which the built-in
    container's Booster.load_model reads; it answers every 4-feature row with the same value,
    so the artifact needs no training library on the runner."""
    tree = {
        "base_weights": [0.25],
        "categories": [],
        "categories_nodes": [],
        "categories_segments": [],
        "categories_sizes": [],
        "default_left": [0],
        "id": 0,
        "left_children": [-1],
        "loss_changes": [0.0],
        "parents": [2147483647],
        "right_children": [-1],
        "split_conditions": [0.25],
        "split_indices": [0],
        "split_type": [0],
        "sum_hessian": [1.0],
        "tree_param": {"num_deleted": "0", "num_feature": "4", "num_nodes": "1", "size_leaf_vector": "0"},
    }
    model = {
        "learner": {
            "attributes": {},
            "feature_names": [],
            "feature_types": [],
            "gradient_booster": {
                "model": {
                    "gbtree_model_param": {"num_parallel_tree": "1", "num_trees": "1", "size_leaf_vector": "0"},
                    "tree_info": [0],
                    "trees": [tree],
                },
                "name": "gbtree",
            },
            "learner_model_param": {"base_score": "5E-1", "num_class": "0", "num_feature": "4", "num_target": "1"},
            "objective": {"name": "reg:squarederror", "reg_loss_param": {"scale_pos_weight": "1"}},
        },
        "version": [1, 7, 6],
    }
    data = json.dumps(model).encode("utf-8")
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        info = tarfile.TarInfo("xgboost-model")
        info.size = len(data)
        tar.addfile(info, io.BytesIO(data))
    return buf.getvalue()


def _create_bucket(ctx, s3, suffix: str) -> str:
    bucket = ctx.unique_name(f"sim2real-sm-{suffix}-")
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(
            Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region}
        )
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(s3, bucket))
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [_MANAGED_TAG]})
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
        Tags=[_MANAGED_TAG],
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
            if "not authorized" in msg or "AssumeRole" in msg:
                last_exc = e
                time.sleep(interval_s)
                continue
            raise
    raise last_exc  # type: ignore[misc]


def _wait_for_endpoint_terminal(
    sm, endpoint_name: str, timeout_s: float = 900.0, interval_s: float = 20.0
) -> dict[str, Any]:
    deadline = time.monotonic() + timeout_s
    desc: dict[str, Any] = {}
    while time.monotonic() < deadline:
        desc = sm.describe_endpoint(EndpointName=endpoint_name)
        if desc["EndpointStatus"] in ("InService", "Failed"):
            return desc
        time.sleep(interval_s)
    raise AssertionError(
        f"endpoint {endpoint_name} did not reach a terminal state within {timeout_s}s: {desc}"
    )


def _poll_for_capture_records(
    s3, bucket: str, prefix: str, timeout_s: float = 240.0, interval_s: float = 15.0
) -> list[dict[str, Any]]:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        resp = s3.list_objects_v2(Bucket=bucket, Prefix=prefix)
        keys = [o["Key"] for o in resp.get("Contents", [])]
        if keys:
            records: list[dict[str, Any]] = []
            for k in keys:
                body = (
                    s3.get_object(Bucket=bucket, Key=k)["Body"].read().decode("utf-8")
                )
                for line in body.splitlines():
                    line = line.strip()
                    if line:
                        records.append(json.loads(line))
            if records:
                return records
        time.sleep(interval_s)
    return []


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
