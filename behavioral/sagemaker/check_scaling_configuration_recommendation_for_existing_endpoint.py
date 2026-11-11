"""scaling-configuration-recommendation-for-existing-endpoint."""
from __future__ import annotations

import io
import json
import tarfile
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "scaling-configuration-recommendation-for-existing-endpoint"
GROUP = "data-plane"
SERVICES = ["sagemaker"]

# GetScalingConfigurationRecommendation requires an already *completed* Inference
# Recommender job. Only an "Advanced" (custom load test) job accepts ResourceLimit, so
# this is held to a single benchmark test (MaxNumberOfTests=1, one Phase) on one
# ml.m5.xlarge with a tiny model; "Default" rejects ResourceLimit outright. Inference
# Recommender deploys and tears down its OWN ephemeral endpoint (not the endpoint from
# CreateEndpoint), which is never nameable again once benchmarking ends, so the
# recommendation is looked up by RecommendationId, not EndpointName (EndpointName gets
# ResourceNotFound). Completion takes about 16 minutes end to end. The point is to catch a
# CreateInferenceRecommendationsJob/GetScalingConfigurationRecommendation stub that fakes
# "Completed" without ever producing a usable recommendation.
_DLC_ACCOUNT_ID = "763104351884"  # AWS Deep Learning Containers registry (most commercial regions)
_HF_MODEL_ID = "hf-internal-testing/tiny-random-distilbert"


@tags("axis:happy-path", "cap:c3", "cap:c4", "plane:control")
def run(ctx) -> None:
    """A completed Inference Recommender job produces >=1 recommendation, and
    GetScalingConfigurationRecommendation against that job + one of its recommendation
    ids returns a non-empty DynamicScalingConfiguration tied to that job."""
    sm = ctx.client("sagemaker")
    iam = ctx.client("iam")
    s3 = ctx.client("s3")

    role_arn = _create_sagemaker_role(ctx, iam)
    # AmazonSageMakerFullAccess grants s3:GetObject only on bucket names containing
    # "sagemaker" (the job's own S3 read of the sample payload gets a 403 otherwise) -- so the
    # bucket name is not
    # cosmetic, it is a permissions boundary the role depends on.
    bucket = ctx.unique_name("sim2real-sagemaker-ir-").lower()
    _create_bucket(ctx, s3, bucket)
    payload_uri = _upload_sample_payload(ctx, s3, bucket)

    group_name = ctx.unique_name("sim2real-ir-mpg-")
    sm.create_model_package_group(
        ModelPackageGroupName=group_name, Tags=[{"Key": "sim2real-check", "Value": CHECK}]
    )
    ctx.on_cleanup(lambda: _cleanup_model_package_group(sm, group_name))

    image_uri = f"{_DLC_ACCOUNT_ID}.dkr.ecr.{ctx.region}.amazonaws.com/huggingface-pytorch-inference:1.13.1-transformers4.26.0-cpu-py39-ubuntu20.04"
    pkg_arn = _retry_iam_propagation(
        lambda: sm.create_model_package(
            ModelPackageGroupName=group_name,
            ModelApprovalStatus="Approved",
            InferenceSpecification={
                "Containers": [
                    {
                        "Image": image_uri,
                        "Environment": {"HF_MODEL_ID": _HF_MODEL_ID, "HF_TASK": "text-classification"},
                    }
                ],
                "SupportedContentTypes": ["application/json"],
                "SupportedResponseMIMETypes": ["application/json"],
                "SupportedRealtimeInferenceInstanceTypes": ["ml.m5.xlarge"],
            },
        )["ModelPackageArn"]
    )

    job_name = ctx.unique_name("sim2real-ir-job-")
    _retry_iam_propagation(
        lambda: sm.create_inference_recommendations_job(
            JobName=job_name,
            # ResourceLimit/TrafficPattern are only accepted by an "Advanced" (custom load
            # test) job -- "Default" (instance-recommendation) rejects them outright with
            # ValidationException("Default JobType will not accept ResourceLimit"). Advanced is
            # also what lets this stay to a SINGLE short load test rather than Default's own
            # multi-instance-type search.
            JobType="Advanced",
            RoleArn=role_arn,
            InputConfig={
                "ModelPackageVersionArn": pkg_arn,
                "ContainerConfig": {
                    "Domain": "NATURAL_LANGUAGE_PROCESSING",
                    "Task": "CLASSIFICATION",
                    "Framework": "PYTORCH",
                    "FrameworkVersion": "1.13",
                    "NearestModelName": "bert-base-cased",
                    "PayloadConfig": {
                        "SamplePayloadUrl": payload_uri,
                        "SupportedContentTypes": ["application/json"],
                    },
                    "SupportedInstanceTypes": ["ml.m5.xlarge"],
                },
                "EndpointConfigurations": [{"InstanceType": "ml.m5.xlarge"}],
                "TrafficPattern": {
                    "TrafficType": "PHASES",
                    "Phases": [{"InitialNumberOfUsers": 1, "SpawnRate": 1, "DurationInSeconds": 120}],
                },
                "ResourceLimit": {"MaxNumberOfTests": 1, "MaxParallelOfTests": 1},
                "JobDurationInSeconds": 1800,
            },
            StoppingConditions={
                "MaxInvocations": 30,
                # ValueInMilliseconds must be 10-50000 (otherwise ValidationException
                # "ModelLatencyThresholds should be between 10 and 50000").
                "ModelLatencyThresholds": [{"Percentile": "P99", "ValueInMilliseconds": 50000}],
            },
            Tags=[{"Key": "sim2real-check", "Value": CHECK}],
        )
    )
    ctx.on_cleanup(lambda: _stop_job_best_effort(sm, job_name))

    description = _poll_until(
        lambda: sm.describe_inference_recommendations_job(JobName=job_name),
        lambda d: d["Status"] in ("COMPLETED", "FAILED", "STOPPED"),
        timeout_s=2700.0,
        interval_s=30.0,
    )
    assert description["Status"] == "COMPLETED", (
        f"inference recommendations job ended in {description['Status']!r}: "
        f"{description.get('FailureReason')}"
    )

    recommendations = description["InferenceRecommendations"]
    assert len(recommendations) >= 1, "completed job produced no recommendations"
    # The job benchmarks its OWN ephemeral endpoint (created and torn down internally), which
    # is never nameable after the fact: passing its EndpointConfiguration.EndpointName as the
    # `EndpointName` lookup key gets ResourceNotFound on real AWS ("Provided RecommendationId
    # or EndpointName was not found under provided job name"). RecommendationId is the
    # identifier the job itself hands back for exactly this case.
    recommendation_id = recommendations[0]["RecommendationId"]

    scaling = sm.get_scaling_configuration_recommendation(
        InferenceRecommendationsJobName=job_name, RecommendationId=recommendation_id
    )
    assert scaling["RecommendationId"] == recommendation_id
    assert scaling["InferenceRecommendationsJobName"] == job_name
    dynamic = scaling["DynamicScalingConfiguration"]
    assert dynamic["MaxCapacity"] >= dynamic["MinCapacity"] >= 1


def _create_bucket(ctx, s3, bucket: str) -> None:
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(
            Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region}
        )
    s3.put_bucket_tagging(
        Bucket=bucket, Tagging={"TagSet": [{"Key": "sim2real-check", "Value": CHECK}]}
    )
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(s3, bucket))


def _empty_and_delete_bucket(s3, bucket: str) -> None:
    for page in s3.get_paginator("list_objects_v2").paginate(Bucket=bucket):
        for obj in page.get("Contents", []):
            s3.delete_object(Bucket=bucket, Key=obj["Key"])
    s3.delete_bucket(Bucket=bucket)


def _upload_sample_payload(ctx, s3, bucket: str) -> str:
    payload_bytes = json.dumps({"inputs": "I really love using SageMaker for this."}).encode()
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        info = tarfile.TarInfo(name="sample_payload.json")
        info.size = len(payload_bytes)
        tar.addfile(info, io.BytesIO(payload_bytes))
    buf.seek(0)
    key = "sample-payload/payload.tar.gz"
    s3.put_object(Bucket=bucket, Key=key, Body=buf.read())
    return f"s3://{bucket}/{key}"


def _create_sagemaker_role(ctx, iam):
    role_name = ctx.unique_name("sim2real-sm-ir-role-")
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "sagemaker.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_policy),
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )["Role"]["Arn"]
    iam.attach_role_policy(
        RoleName=role_name,
        PolicyArn="arn:aws:iam::aws:policy/AmazonSageMakerFullAccess",
    )

    def _cleanup():
        try:
            iam.detach_role_policy(
                RoleName=role_name, PolicyArn="arn:aws:iam::aws:policy/AmazonSageMakerFullAccess"
            )
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise
        iam.delete_role(RoleName=role_name)

    ctx.on_cleanup(_cleanup)
    return role_arn


def _cleanup_model_package_group(sm, group_name: str) -> None:
    resp = sm.list_model_packages(ModelPackageGroupName=group_name)
    for summary in resp.get("ModelPackageSummaryList", []):
        sm.delete_model_package(ModelPackageName=summary["ModelPackageArn"])
    sm.delete_model_package_group(ModelPackageGroupName=group_name)


def _stop_job_best_effort(sm, job_name: str) -> None:
    """Stop the recommendations job unless it already ended; a stop that leaves it running raises."""
    running = ("PENDING", "IN_PROGRESS")
    if sm.describe_inference_recommendations_job(JobName=job_name)["Status"] not in running:
        return
    try:
        sm.stop_inference_recommendations_job(JobName=job_name)
    except ClientError:
        # A job that ended between the describe and the stop is refused; that is not a failure.
        if sm.describe_inference_recommendations_job(JobName=job_name)["Status"] in running:
            raise


def _retry_iam_propagation(fn, attempts: int = 6, delay_s: float = 15.0):
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


def _poll_until(probe, predicate, *, timeout_s: float = 60.0, interval_s: float = 3.0):
    deadline = time.monotonic() + timeout_s
    value = probe()
    while time.monotonic() < deadline:
        value = probe()
        if predicate(value):
            return value
        time.sleep(interval_s)
    return value


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
