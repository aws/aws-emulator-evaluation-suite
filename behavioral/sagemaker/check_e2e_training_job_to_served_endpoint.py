"""e2e-training-job-to-served-endpoint."""
from __future__ import annotations

import json
import random
import time

from behavioral_harness import tags

CHECK = "e2e-training-job-to-served-endpoint"
GROUP = "e2e"
SERVICES = ["sagemaker"]

# Well-known per-region ECR registry accounts that host the SageMaker built-in
# "linear-learner" algorithm image (same image serves training and inference).
_LINEAR_LEARNER_REGISTRY = {
    "us-east-1": "382416733822",
    "us-east-2": "404615174143",
    "us-west-1": "632365934929",
    "us-west-2": "174872318107",
    "eu-west-1": "438346466558",
    "eu-central-1": "664544806723",
    "ap-northeast-1": "351501993468",
    "ap-northeast-2": "835164637446",
    "ap-southeast-1": "121021644041",
    "ap-southeast-2": "783357654285",
    "ap-south-1": "991648021394",
    "ca-central-1": "469771592824",
}


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:e2e", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A training job's model artifact deployed via CreateModel/EndpointConfig/Endpoint reaches
    InService referencing that exact model and artifact, and DeleteEndpoint then leaves the
    endpoint not found."""
    sm = ctx.client("sagemaker")
    role_arn = _create_sagemaker_role(ctx)
    job_name, model_artifacts, image = _run_linear_learner_training_job(ctx, role_arn)

    model_name = ctx.unique_name("sim2real-sm-e2e-model-")
    sm.create_model(
        ModelName=model_name,
        PrimaryContainer={"Image": image, "ModelDataUrl": model_artifacts},
        ExecutionRoleArn=role_arn,
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: sm.delete_model(ModelName=model_name))

    config_name = ctx.unique_name("sim2real-sm-e2e-epc-")
    sm.create_endpoint_config(
        EndpointConfigName=config_name,
        ProductionVariants=[
            {
                "VariantName": "AllTraffic",
                "ModelName": model_name,
                "InstanceType": "ml.m5.large",
                "InitialInstanceCount": 1,
            }
        ],
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: sm.delete_endpoint_config(EndpointConfigName=config_name))

    endpoint_name = ctx.unique_name("sim2real-sm-e2e-ep-")
    sm.create_endpoint(
        EndpointName=endpoint_name,
        EndpointConfigName=config_name,
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )

    endpoint_deleted = {"done": False}

    def _delete_endpoint_if_needed():
        if not endpoint_deleted["done"]:
            from botocore.exceptions import ClientError

            # A still-Creating endpoint refuses the delete with ValidationException: retried
            # for 600 s.
            deadline = time.monotonic() + 600
            while True:
                try:
                    sm.delete_endpoint(EndpointName=endpoint_name)
                    return
                except ClientError as err:
                    error = err.response["Error"]
                    if error["Code"] != "ValidationException":
                        raise
                    if "Could not find" in error.get("Message", ""):
                        return
                    if time.monotonic() >= deadline:
                        raise
                time.sleep(2)

    ctx.on_cleanup(_delete_endpoint_if_needed)

    desc = _poll_until(
        probe=lambda: sm.describe_endpoint(EndpointName=endpoint_name),
        predicate=lambda d: d["EndpointStatus"] in ("InService", "Failed"),
        timeout_s=900,
        interval_s=20,
    )
    assert desc["EndpointStatus"] == "InService", (
        f"endpoint did not reach InService: expected 'InService', got "
        f"{desc['EndpointStatus']!r} ({desc.get('FailureReason')})"
    )
    assert desc["EndpointConfigName"] == config_name, (
        f"endpoint references config {desc['EndpointConfigName']!r}, expected {config_name!r}"
    )

    desc_cfg = sm.describe_endpoint_config(EndpointConfigName=config_name)
    assert desc_cfg["ProductionVariants"][0]["ModelName"] == model_name, (
        f"endpoint config's production variant references model "
        f"{desc_cfg['ProductionVariants'][0]['ModelName']!r}, expected {model_name!r}"
    )

    desc_model = sm.describe_model(ModelName=model_name)
    assert desc_model["PrimaryContainer"]["ModelDataUrl"] == model_artifacts, (
        f"model's container references artifact "
        f"{desc_model['PrimaryContainer']['ModelDataUrl']!r}, expected {model_artifacts!r}"
    )

    desc_job = sm.describe_training_job(TrainingJobName=job_name)
    assert desc_job["ModelArtifacts"]["S3ModelArtifacts"] == model_artifacts, (
        f"training job's own artifact record {desc_job['ModelArtifacts']['S3ModelArtifacts']!r} "
        f"no longer matches the artifact deployed to the endpoint {model_artifacts!r}"
    )
    assert desc_job["TrainingJobStatus"] == "Completed", (
        f"training job status regressed to {desc_job['TrainingJobStatus']!r}, expected 'Completed'"
    )

    sm.delete_endpoint(EndpointName=endpoint_name)
    endpoint_deleted["done"] = True

    code, message = _refusal_eventually(
        lambda: sm.describe_endpoint(EndpointName=endpoint_name), timeout_s=120, interval_s=5
    )
    assert code == "ValidationException", (
        f"describe_endpoint on the deleted endpoint returned code {code!r}, "
        f"expected 'ValidationException'"
    )
    expected = f'Could not find endpoint "{endpoint_name}".'
    assert message == expected, f"expected message {expected!r}, got {message!r}"


# ===== helpers =====
def _refusal_eventually(fn, *, timeout_s, interval_s):
    """Poll fn() until it is refused; return the refusal's (code, message). A call that still
    SUCCEEDS at the deadline raises: the deleted resource must stop being describable."""
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    result = None
    while time.monotonic() < deadline:
        try:
            result = fn()
        except ClientError as err:
            e = err.response["Error"]
            return e["Code"], e.get("Message")
        time.sleep(interval_s)
    raise AssertionError(
        f"expected the call to be rejected within {timeout_s}s, but it still SUCCEEDED and "
        f"returned {result!r}"
    )


def _poll_until(probe, predicate, *, timeout_s: float, interval_s: float):
    deadline = time.monotonic() + timeout_s
    value = probe()
    while not predicate(value):
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"condition not met within {timeout_s}s, last value: {value!r}"
            )
        time.sleep(interval_s)
        value = probe()
    return value


def _create_training_job_retrying_role_propagation(sm, *, timeout_s: float = 60.0, interval_s: float = 5.0, **kwargs):
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    while True:
        try:
            sm.create_training_job(**kwargs)
            return
        except ClientError:
            # A role's trust policy is not instantly visible to the SageMaker control
            # plane after IAM reports the role as created; retry the real dependent
            # call itself rather than sleeping blind before making it.
            if time.monotonic() >= deadline:
                raise
            time.sleep(interval_s)


def _create_sagemaker_role(ctx):
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-sm-e2e-role-")
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
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]["Arn"]
    policy_arn = "arn:aws:iam::aws:policy/AmazonSageMakerFullAccess"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)

    def _cleanup():
        from botocore.exceptions import ClientError

        for delete in (
            lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=policy_arn),
            lambda: iam.delete_role(RoleName=role_name),
        ):
            try:
                delete()
            except ClientError as err:
                if err.response["Error"]["Code"] != "NoSuchEntity":
                    raise

    ctx.on_cleanup(_cleanup)

    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        try:
            iam.get_role(RoleName=role_name)
            break
        except Exception:
            time.sleep(2)
    return role_arn


def _linear_learner_image(region):
    account = _LINEAR_LEARNER_REGISTRY.get(region)
    if not account:
        raise AssertionError(
            f"no known linear-learner built-in algorithm registry account for "
            f"region {region!r}; extend _LINEAR_LEARNER_REGISTRY to close this gap"
        )
    return f"{account}.dkr.ecr.{region}.amazonaws.com/linear-learner:1"


def _upload_training_data(ctx):
    s3 = ctx.client("s3")
    # AmazonSageMakerFullAccess only grants s3:GetObject/PutObject on buckets whose
    # name contains "sagemaker" -- confirmed on real AWS, where a bucket without
    # that substring makes the training job's data download fail AccessDenied.
    bucket = ctx.unique_name("sim2real-sagemaker-e2e-data-").lower()
    region = ctx.region
    if region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(
            Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": region}
        )
    s3.put_bucket_tagging(
        Bucket=bucket, Tagging={"TagSet": [{"Key": "sim2real", "Value": CHECK}]}
    )

    def _cleanup():
        from botocore.exceptions import ClientError

        try:
            objs = s3.list_objects_v2(Bucket=bucket).get("Contents", [])
            for obj in objs:
                s3.delete_object(Bucket=bucket, Key=obj["Key"])
            s3.delete_bucket(Bucket=bucket)
        except ClientError as err:
            if err.response["Error"]["Code"] != "NoSuchBucket":
                raise

    ctx.on_cleanup(_cleanup)

    rng = random.Random(42)
    rows = []
    for _ in range(200):
        f1, f2, f3 = rng.random(), rng.random(), rng.random()
        label = f1 * 2.0 + f2 - f3 + rng.random() * 0.01
        rows.append(f"{label},{f1},{f2},{f3}")
    key = "train/data.csv"
    s3.put_object(Bucket=bucket, Key=key, Body="\n".join(rows).encode("utf-8"))
    return bucket, key


def _run_linear_learner_training_job(ctx, role_arn):
    sm = ctx.client("sagemaker")
    bucket, key = _upload_training_data(ctx)
    image = _linear_learner_image(ctx.region)
    job_name = ctx.unique_name("sim2real-sm-e2e-train-")

    _create_training_job_retrying_role_propagation(
        sm,
        TrainingJobName=job_name,
        AlgorithmSpecification={"TrainingImage": image, "TrainingInputMode": "File"},
        RoleArn=role_arn,
        InputDataConfig=[
            {
                "ChannelName": "train",
                "DataSource": {
                    "S3DataSource": {
                        "S3DataType": "S3Prefix",
                        "S3Uri": f"s3://{bucket}/{key}",
                        "S3DataDistributionType": "FullyReplicated",
                    }
                },
                "ContentType": "text/csv",
                "CompressionType": "None",
            }
        ],
        OutputDataConfig={"S3OutputPath": f"s3://{bucket}/output/"},
        ResourceConfig={"InstanceType": "ml.m5.large", "InstanceCount": 1, "VolumeSizeInGB": 5},
        StoppingCondition={"MaxRuntimeInSeconds": 900},
        HyperParameters={
            "feature_dim": "3",
            "predictor_type": "regressor",
            "mini_batch_size": "20",
            "epochs": "3",
        },
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )

    def _cleanup():
        from botocore.exceptions import ClientError

        try:
            sm.stop_training_job(TrainingJobName=job_name)
        except ClientError as exc:
            # A job that is not InProgress refuses the stop with ValidationException; anything else fails.
            if exc.response["Error"]["Code"] != "ValidationException" or sm.describe_training_job(TrainingJobName=job_name)["TrainingJobStatus"] == "InProgress":
                raise

    ctx.on_cleanup(_cleanup)

    desc = _poll_until(
        probe=lambda: sm.describe_training_job(TrainingJobName=job_name),
        predicate=lambda d: d["TrainingJobStatus"] in ("Completed", "Failed", "Stopped"),
        timeout_s=900,
        interval_s=15,
    )
    if desc["TrainingJobStatus"] != "Completed":
        raise AssertionError(
            f"training job did not complete: status={desc['TrainingJobStatus']} "
            f"reason={desc.get('FailureReason')}"
        )
    return job_name, desc["ModelArtifacts"]["S3ModelArtifacts"], image


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
