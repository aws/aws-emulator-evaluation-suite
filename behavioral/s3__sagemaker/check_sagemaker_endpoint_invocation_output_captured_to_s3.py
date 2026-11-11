"""sagemaker-endpoint-invocation-output-captured-to-s3."""
from __future__ import annotations

import json
import time
from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "sagemaker-endpoint-invocation-output-captured-to-s3"
GROUP = "event-propagation"
SERVICES = ["s3", "sagemaker"]

_TAG = [{"Key": "sim2real", "Value": "data-capture-to-s3"}]

_XGBOOST_REGISTRY_ACCOUNTS = {
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


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "concern:e2e", "dp:api", "plane:data")
def run(ctx: Any) -> None:
    """An endpoint with DataCaptureConfig writes capture files under its name to the configured S3 prefix,
    and one of them pairs the invocation's endpointInput with an endpointOutput score in [0, 1]: both
    the request and the response legs are delivered."""
    image = _xgboost_image_uri(ctx.region)

    s3 = ctx.client("s3")
    sm = ctx.client("sagemaker")
    smrt = ctx.client("sagemaker-runtime")

    bucket = _create_bucket(ctx)
    role = _create_role(ctx, bucket)

    s3.put_object(Bucket=bucket, Key="train/train.csv", Body=_xgboost_training_csv().encode("utf-8"))

    job_name = ctx.unique_name("sim2real-sm-train-")
    _call_with_role_propagation_retry(
        lambda: sm.create_training_job(
            TrainingJobName=job_name,
            AlgorithmSpecification={"TrainingImage": image, "TrainingInputMode": "File"},
            RoleArn=role["arn"],
            InputDataConfig=[{
                "ChannelName": "train",
                "ContentType": "text/csv",
                "DataSource": {"S3DataSource": {
                    "S3DataType": "S3Prefix",
                    "S3Uri": f"s3://{bucket}/train/",
                    "S3DataDistributionType": "FullyReplicated",
                }},
            }],
            OutputDataConfig={"S3OutputPath": f"s3://{bucket}/output/"},
            ResourceConfig={"InstanceType": "ml.m5.large", "InstanceCount": 1, "VolumeSizeInGB": 5},
            StoppingCondition={"MaxRuntimeInSeconds": 1800},
            HyperParameters={"objective": "binary:logistic", "num_round": "10"},
            Tags=_TAG,
        )
    )
    train_desc = _poll_until(
        lambda: sm.describe_training_job(TrainingJobName=job_name),
        lambda d: d["TrainingJobStatus"] in ("Completed", "Failed", "Stopped"),
        timeout_s=900,
        interval_s=20,
    )
    assert train_desc["TrainingJobStatus"] == "Completed", (
        f"expected training job {job_name} to complete, got "
        f"{train_desc['TrainingJobStatus']}: {train_desc.get('FailureReason')}"
    )
    model_data_url = train_desc["ModelArtifacts"]["S3ModelArtifacts"]

    model_name = ctx.unique_name("sim2real-sm-model-")
    _call_with_role_propagation_retry(
        lambda: sm.create_model(
            ModelName=model_name,
            PrimaryContainer={"Image": image, "ModelDataUrl": model_data_url},
            ExecutionRoleArn=role["arn"],
            Tags=_TAG,
        )
    )
    ctx.on_cleanup(lambda: sm.delete_model(ModelName=model_name))

    capture_prefix = "capture"
    endpoint_config_name = ctx.unique_name("sim2real-sm-epc-")
    sm.create_endpoint_config(
        EndpointConfigName=endpoint_config_name,
        ProductionVariants=[{
            "VariantName": "AllTraffic",
            "ModelName": model_name,
            "InitialInstanceCount": 1,
            "InstanceType": "ml.m5.large",
        }],
        DataCaptureConfig={
            "EnableCapture": True,
            "InitialSamplingPercentage": 100,
            "DestinationS3Uri": f"s3://{bucket}/{capture_prefix}",
            "CaptureOptions": [{"CaptureMode": "Input"}, {"CaptureMode": "Output"}],
            "CaptureContentTypeHeader": {"CsvContentTypes": ["text/csv"]},
        },
        Tags=_TAG,
    )
    ctx.on_cleanup(lambda: sm.delete_endpoint_config(EndpointConfigName=endpoint_config_name))

    endpoint_name = ctx.unique_name("sim2real-sm-ep-")
    sm.create_endpoint(EndpointName=endpoint_name, EndpointConfigName=endpoint_config_name, Tags=_TAG)
    ctx.on_cleanup(lambda: sm.delete_endpoint(EndpointName=endpoint_name))

    ep_desc = _poll_until(
        lambda: sm.describe_endpoint(EndpointName=endpoint_name),
        lambda d: d["EndpointStatus"] in ("InService", "Failed"),
        timeout_s=900,
        interval_s=20,
    )
    assert ep_desc["EndpointStatus"] == "InService", (
        f"expected endpoint {endpoint_name} InService, got "
        f"{ep_desc['EndpointStatus']}: {ep_desc.get('FailureReason')}"
    )

    sentinel_payload = "0.9,0.9"
    invoke_resp = smrt.invoke_endpoint(EndpointName=endpoint_name, ContentType="text/csv", Body=sentinel_payload)
    invoke_output = invoke_resp["Body"].read().decode("utf-8").strip()
    invoke_score = float(invoke_output.splitlines()[0])
    assert 0.0 <= invoke_score <= 1.0, (
        f"invoke_endpoint returned {invoke_output!r}, not a plausible binary:logistic "
        "probability -- the positive control invocation itself is suspect"
    )

    captured = _poll_until(
        lambda: _list_capture_objects(s3, bucket, capture_prefix),
        lambda keys: len(keys) > 0,
        timeout_s=300,
        interval_s=15,
    )
    assert captured, (
        f"no data-capture objects ever landed under s3://{bucket}/{capture_prefix} "
        f"after invoking {endpoint_name}"
    )

    found_pair = False
    for key in captured:
        # The capture record body carries no endpoint identity (eventMetadata has no
        # endpointName field) -- SageMaker correlates captures to endpoints structurally,
        # via the .../{endpoint-name}/{variant-name}/... object key path it writes to.
        assert endpoint_name in key, (
            f"capture object key {key!r} does not reference our endpoint {endpoint_name!r}"
        )
        body = s3.get_object(Bucket=bucket, Key=key)["Body"].read().decode("utf-8")
        for line in body.splitlines():
            if not line.strip():
                continue
            record = json.loads(line)
            input_text = _capture_field_text(record["captureData"]["endpointInput"])
            if sentinel_payload not in input_text:
                continue
            output_text = _capture_field_text(record["captureData"]["endpointOutput"]).strip()
            output_score = float(output_text.splitlines()[0])
            assert 0.0 <= output_score <= 1.0, (
                f"capture record at s3://{bucket}/{key} paired our sentinel input with "
                f"captured output {output_text!r}, not a plausible binary:logistic probability"
            )
            found_pair = True
    assert found_pair, (
        "no captured record paired the sentinel input payload with a captured, plausible "
        "endpointOutput -- data capture may be recording the request but never the response"
    )


def _xgboost_image_uri(region: str) -> str:
    account = _XGBOOST_REGISTRY_ACCOUNTS.get(region)
    if account is None:
        raise AssertionError(
            f"no known SageMaker built-in XGBoost ECR registry account hardcoded for region "
            f"{region!r} (AWS retired the per-region Docker-registry-path doc table; only a "
            "subset of regions is mapped here) -- add the account id to close this gap"
        )
    return f"{account}.dkr.ecr.{region}.amazonaws.com/sagemaker-xgboost:1.7-1"


def _capture_field_text(node: dict) -> str:
    data = node["data"]
    if node.get("encoding") == "BASE64":
        import base64
        return base64.b64decode(data).decode("utf-8", errors="replace")
    return data


def _call_with_role_propagation_retry(fn, timeout_s: float = 90.0, interval_s: float = 5.0):
    """SageMaker may not yet be able to assume a just-created role; retry the specific
    AssumeRole-not-authorized error within a bound instead of sleeping unconditionally."""
    deadline = time.monotonic() + timeout_s
    last_exc: ClientError | None = None
    while time.monotonic() < deadline:
        try:
            return fn()
        except ClientError as exc:
            msg = str(exc).lower()
            if "assume role" not in msg and "not authorized" not in msg:
                raise
            last_exc = exc
            time.sleep(interval_s)
    raise last_exc  # type: ignore[misc]


def _xgboost_training_csv(n_rows: int = 40) -> str:
    import random
    rng = random.Random(1234)
    lines = []
    for i in range(n_rows):
        label = i % 2
        f1 = rng.uniform(0, 1) + label * 3.0
        f2 = rng.uniform(0, 1) + label * 3.0
        lines.append(f"{label},{f1:.4f},{f2:.4f}")
    return "\n".join(lines) + "\n"


def _list_capture_objects(s3, bucket: str, prefix: str) -> list[str]:
    resp = s3.list_objects_v2(Bucket=bucket, Prefix=prefix)
    return [o["Key"] for o in resp.get("Contents", [])]


def _poll_until(probe, predicate, timeout_s: float = 600.0, interval_s: float = 15.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last value={last}")


def _create_bucket(ctx: Any) -> str:
    s3 = ctx.client("s3")
    name = ctx.unique_name("sim2real-sm-s3-").lower()
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=name)
    else:
        s3.create_bucket(Bucket=name, CreateBucketConfiguration={"LocationConstraint": ctx.region})
    s3.put_bucket_tagging(Bucket=name, Tagging={"TagSet": _TAG})

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
    role = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust), Tags=_TAG)
    role_arn = role["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    policy_arn = "arn:aws:iam::aws:policy/AmazonSageMakerFullAccess"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=policy_arn))

    # AmazonSageMakerFullAccess scopes its own S3 statements to buckets/keys whose name
    # contains "sagemaker"; our bucket does not, so grant this specific bucket explicitly.
    s3_policy_name = f"{role_name}-s3"
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName=s3_policy_name,
        PolicyDocument=json.dumps({
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Action": ["s3:GetObject", "s3:PutObject", "s3:ListBucket"],
                "Resource": [f"arn:aws:s3:::{bucket}", f"arn:aws:s3:::{bucket}/*"],
            }],
        }),
    )
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=s3_policy_name))
    return {"arn": role_arn, "name": role_name}


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
