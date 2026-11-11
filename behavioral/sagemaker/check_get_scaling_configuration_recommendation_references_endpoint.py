"""get-scaling-configuration-recommendation-references-endpoint."""
from __future__ import annotations

import io
import tarfile
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "get-scaling-configuration-recommendation-references-endpoint"
GROUP = "data-plane"
SERVICES = ["sagemaker"]

_XGBOOST_VERSION = "1.5-1"

#: The record the benchmark replays; two features because the training CSV is `label,f1,f2`.
_SAMPLE_PAYLOAD = b"1.0,2.0\n"
_SAMPLE_CONTENT_TYPE = "text/csv"

#: Inference Recommender matches `ContainerConfig` against its zoo of reference models
#: (`ListModelMetaData`). `Task` and `NearestModelName` must name a zoo row, or the job ends
#: FAILED INVALID_INPUT after a healthy load test; `FrameworkVersion` need not match.
_NEAREST_MODEL_NAME = "xgboost"
_TASK = "CLASSIFICATION"  # the training objective below is binary:logistic

# Inline policy on the execution role; AmazonSageMakerFullAccess does not cover this bucket.
_S3_POLICY = "sim2real-scalerec-bucket-read"


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """A completed Inference Recommender job that benchmarked a user-owned endpoint lists it in
    EndpointPerformances, and GetScalingConfigurationRecommendation by that EndpointName echoes it
    with a DynamicScalingConfiguration whose capacity bounds are ordered.
    """
    sm = ctx.client("sagemaker")
    s3 = ctx.client("s3")
    iam = ctx.client("iam")
    region = ctx.region

    training_image = _xgboost_image_uri(region, _XGBOOST_VERSION)

    bucket = ctx.unique_name("sim2real-sm-scalerec-").lower().replace("_", "-")
    if region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": region})
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(s3, bucket))

    role_arn = _create_sagemaker_execution_role(ctx, iam, bucket)

    train_csv = "\n".join(
        f"{i % 2},{float(i)},{float(i) * 2.0}" for i in range(40)
    ).encode("utf-8")
    train_key = "train/train.csv"
    s3.put_object(Bucket=bucket, Key=train_key, Body=train_csv)
    train_uri = f"s3://{bucket}/{train_key}"
    output_uri = f"s3://{bucket}/output/"

    training_job_name = ctx.unique_name("sim2real-scalerec-train-")
    _retry_iam_propagation(
        lambda: sm.create_training_job(
            TrainingJobName=training_job_name,
            AlgorithmSpecification={"TrainingImage": training_image, "TrainingInputMode": "File"},
            RoleArn=role_arn,
            HyperParameters={"objective": "binary:logistic", "num_round": "5"},
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
            OutputDataConfig={"S3OutputPath": output_uri},
            ResourceConfig={"InstanceType": "ml.m5.large", "InstanceCount": 1, "VolumeSizeInGB": 5},
            StoppingCondition={"MaxRuntimeInSeconds": 900},
            Tags=[{"Key": "sim2real", "Value": CHECK}],
        )
    )
    ctx.on_cleanup(lambda: _best_effort(lambda: sm.stop_training_job(TrainingJobName=training_job_name)))

    training_job = _poll_until(
        lambda: sm.describe_training_job(TrainingJobName=training_job_name),
        lambda j: j["TrainingJobStatus"] in ("Completed", "Failed", "Stopped"),
        timeout_s=900.0,
        interval_s=20.0,
    )
    assert training_job["TrainingJobStatus"] == "Completed", (
        f"training job did not complete: {training_job['TrainingJobStatus']} "
        f"({training_job.get('FailureReason')})"
    )
    model_artifacts = training_job["ModelArtifacts"]["S3ModelArtifacts"]

    model_name = ctx.unique_name("sim2real-scalerec-model-")
    sm.create_model(
        ModelName=model_name,
        ExecutionRoleArn=role_arn,
        PrimaryContainer={"Image": training_image, "ModelDataUrl": model_artifacts},
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: sm.delete_model(ModelName=model_name))

    endpoint_config_name = ctx.unique_name("sim2real-scalerec-epc-")
    sm.create_endpoint_config(
        EndpointConfigName=endpoint_config_name,
        ProductionVariants=[
            {
                "VariantName": "AllTraffic",
                "ModelName": model_name,
                "InitialInstanceCount": 1,
                "InstanceType": "ml.m5.large",
            }
        ],
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: sm.delete_endpoint_config(EndpointConfigName=endpoint_config_name))

    endpoint_name = ctx.unique_name("sim2real-scalerec-ep-")
    sm.create_endpoint(
        EndpointName=endpoint_name,
        EndpointConfigName=endpoint_config_name,
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: sm.delete_endpoint(EndpointName=endpoint_name))

    endpoint = _poll_until(
        lambda: sm.describe_endpoint(EndpointName=endpoint_name),
        lambda e: e["EndpointStatus"] in ("InService", "Failed"),
        timeout_s=900.0,
        interval_s=20.0,
    )
    assert endpoint["EndpointStatus"] == "InService", (
        f"endpoint failed to deploy: {endpoint.get('FailureReason')}"
    )

    # Positive control before the long benchmark: a payload error surfaces here with the
    # container's own message instead of the job's generic "Inspect model request" failure.
    smr = ctx.client("sagemaker-runtime")
    invoked = smr.invoke_endpoint(
        EndpointName=endpoint_name, ContentType=_SAMPLE_CONTENT_TYPE, Body=_SAMPLE_PAYLOAD
    )
    prediction = invoked["Body"].read()
    assert prediction.strip(), (
        f"endpoint {endpoint_name!r} returned an empty body for the sample payload "
        f"{_SAMPLE_PAYLOAD!r}; the benchmark below could not succeed either"
    )

    payload_key = "payload/sample.tar.gz"
    payload_uri = f"s3://{bucket}/{payload_key}"
    _upload_sample_payload_tarball(s3, bucket, payload_key, _SAMPLE_PAYLOAD)

    job_name = ctx.unique_name("sim2real-scalerec-job-")
    sm.create_inference_recommendations_job(
        JobName=job_name,
        JobType="Default",
        RoleArn=role_arn,
        InputConfig={
            # ModelName (or ModelPackageVersionArn, exactly one) is required even when Endpoints
            # names an existing endpoint.
            "ModelName": model_name,
            "Endpoints": [{"EndpointName": endpoint_name}],
            "ContainerConfig": {
                # The zoo key; see _NEAREST_MODEL_NAME/_TASK above.
                "Domain": "MACHINE_LEARNING",
                "Task": _TASK,
                "Framework": "XGBOOST",
                "FrameworkVersion": _XGBOOST_VERSION,
                "NearestModelName": _NEAREST_MODEL_NAME,
                "PayloadConfig": {
                    "SamplePayloadUrl": payload_uri,
                    "SupportedContentTypes": [_SAMPLE_CONTENT_TYPE],
                },
                # The built-in XGBoost container answers in text/csv.
                "SupportedResponseMIMETypes": [_SAMPLE_CONTENT_TYPE],
                "SupportedInstanceTypes": ["ml.m5.large"],
                "SupportedEndpointType": "RealTime",
            },
            # No JobDurationInSeconds: a Default job rejects it (Advanced-only field).
        },
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(
        lambda: _best_effort(
            lambda: sm.stop_inference_recommendations_job(JobName=job_name)
        )
    )

    job = _poll_until(
        lambda: sm.describe_inference_recommendations_job(JobName=job_name),
        lambda j: j["Status"] in ("COMPLETED", "FAILED", "STOPPED"),
        timeout_s=2400.0,
        interval_s=30.0,
    )
    assert job["Status"] == "COMPLETED", (
        f"inference recommendations job did not complete: {job['Status']} "
        f"({job.get('FailureReason')}); per-benchmark steps: "
        f"{_benchmark_step_failures(sm, job_name)}"
    )

    # A user-supplied endpoint is reported under EndpointPerformances[].EndpointInfo, unlike the
    # EndpointConfiguration shape InferenceRecommendations uses for the job's own endpoint.
    benchmarked = [
        p["EndpointInfo"]["EndpointName"] for p in job.get("EndpointPerformances", [])
    ]
    assert endpoint_name in benchmarked, (
        f"the live endpoint was not among the benchmarked endpoints: {benchmarked!r} "
        f"does not contain {endpoint_name!r}"
    )

    recommendation = sm.get_scaling_configuration_recommendation(
        InferenceRecommendationsJobName=job_name,
        EndpointName=endpoint_name,
    )
    assert recommendation["EndpointName"] == endpoint_name, (
        f"recommendation is not tied to the benchmarked endpoint: "
        f"{recommendation.get('EndpointName')!r} != {endpoint_name!r}"
    )
    assert recommendation["InferenceRecommendationsJobName"] == job_name
    dynamic_config = recommendation["DynamicScalingConfiguration"]
    assert dynamic_config["MinCapacity"] >= 1
    assert dynamic_config["MaxCapacity"] >= dynamic_config["MinCapacity"]


#: The built-in XGBoost image's ECR registry account per region, from the sagemaker SDK's
#: image_uri_config/xgboost.json.
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


def _xgboost_image_uri(region: str, version: str) -> str:
    account = _XGB_REGISTRY_ACCOUNTS.get(region)
    if account is None:
        raise AssertionError(
            f"no SageMaker built-in XGBoost ECR registry account mapped for region {region!r} "
            "- add it from the SDK's image_uri_config/xgboost.json to close this gap"
        )
    return f"{account}.dkr.ecr.{region}.amazonaws.com/sagemaker-xgboost:{version}"


def _benchmark_step_failures(sm, job_name: str):
    """Per-benchmark step verdicts, since a failed job's top-level FailureReason is generic."""
    try:
        steps = sm.list_inference_recommendations_job_steps(JobName=job_name)["Steps"]
    except Exception as exc:  # noqa: BLE001
        return f"<could not list job steps: {exc}>"
    return [
        {
            "status": s.get("Status"),
            "endpoint": s.get("InferenceBenchmark", {})
            .get("EndpointConfiguration", {})
            .get("EndpointName"),
            "reason": s.get("InferenceBenchmark", {}).get("FailureReason"),
        }
        for s in steps
    ]


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition never became true within {timeout_s}s; last value: {last!r}")


def _best_effort(fn):
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("NoSuchEntity", "ResourceNotFound"):
            raise


def _empty_and_delete_bucket(s3, bucket: str) -> None:
    paginator = s3.get_paginator("list_objects_v2")
    for page in paginator.paginate(Bucket=bucket):
        objects = [{"Key": o["Key"]} for o in page.get("Contents", [])]
        if objects:
            failed = s3.delete_objects(Bucket=bucket, Delete={"Objects": objects}).get("Errors")
            if failed:
                raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
    s3.delete_bucket(Bucket=bucket)


def _upload_sample_payload_tarball(s3, bucket: str, key: str, sample_csv_bytes: bytes) -> None:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        info = tarfile.TarInfo(name="sample.csv")
        info.size = len(sample_csv_bytes)
        tar.addfile(info, io.BytesIO(sample_csv_bytes))
    s3.put_object(Bucket=bucket, Key=key, Body=buf.getvalue())


def _create_sagemaker_execution_role(ctx, iam, bucket: str):
    role_name = ctx.unique_name("sim2real-sm-scalerec-role-")
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "sagemaker.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    import json

    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_policy),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    role_arn = role["Role"]["Arn"]

    def cleanup_role():
        # Inline policies must go before the role itself, or DeleteRole fails with
        # DeleteConflict and the role is stranded.
        _best_effort(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=_S3_POLICY))
        _best_effort(
            lambda: iam.detach_role_policy(
                RoleName=role_name,
                PolicyArn="arn:aws:iam::aws:policy/AmazonSageMakerFullAccess",
            )
        )
        _best_effort(lambda: iam.delete_role(RoleName=role_name))

    ctx.on_cleanup(cleanup_role)
    iam.attach_role_policy(
        RoleName=role_name,
        PolicyArn="arn:aws:iam::aws:policy/AmazonSageMakerFullAccess",
    )
    # AmazonSageMakerFullAccess grants S3 only on buckets whose name contains "sagemaker", so
    # this bucket needs an explicit grant.
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName=_S3_POLICY,
        PolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": ["s3:GetObject", "s3:PutObject", "s3:DeleteObject"],
                        "Resource": f"arn:aws:s3:::{bucket}/*",
                    },
                    {
                        "Effect": "Allow",
                        "Action": ["s3:ListBucket", "s3:GetBucketLocation"],
                        "Resource": f"arn:aws:s3:::{bucket}",
                    },
                ],
            }
        ),
    )
    return role_arn


def _retry_iam_propagation(fn, attempts: int = 8, delay_s: float = 15.0):
    """IAM role/policy attachment is eventually consistent; retry the first SageMaker
    call that assumes the role instead of guessing how long propagation takes."""
    last_exc = None
    for _ in range(attempts):
        try:
            return fn()
        except Exception as exc:  # noqa: BLE001
            code = getattr(exc, "response", {}).get("Error", {}).get("Code", "")
            if code in ("ValidationException", "AccessDeniedException"):
                last_exc = exc
                time.sleep(delay_s)
                continue
            raise
    raise last_exc


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
