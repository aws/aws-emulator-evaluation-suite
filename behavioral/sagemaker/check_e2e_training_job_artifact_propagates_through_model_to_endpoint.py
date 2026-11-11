"""e2e-training-job-artifact-propagates-through-model-to-endpoint."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "e2e-training-job-artifact-propagates-through-model-to-endpoint"
GROUP = "state-machine"
SERVICES = ["sagemaker"]

# Public built-in-algorithm ECR registry account IDs, keyed by region. These are the
# well-known first-generation SageMaker built-in algorithm image accounts (linear-learner,
# kmeans, pca, ...) that are stable and documented across AWS regions. The keys are a
# read-only reference table, not a region override: the check always trains and deploys
# in `ctx.region`, using this table only to resolve which account hosts that region's
# copy of the image.
_ALGO_REGISTRY_ACCOUNTS = {
    "us-east-1": "382416733822",
    "us-east-2": "404615174143",
    "us-west-1": "632365934929",
    "us-west-2": "174872318107",
    "ca-central-1": "469771592824",
    "eu-west-1": "438346466558",
    "eu-west-2": "644912444149",
    "eu-west-3": "749696950732",
    "eu-central-1": "664544806723",
    "eu-north-1": "669576153137",
    "ap-southeast-1": "475088953585",
    "ap-southeast-2": "712309505854",
    "ap-northeast-1": "501404015308",
    "ap-northeast-2": "306986355934",
    "ap-south-1": "991648021394",
    "sa-east-1": "855470959533",
}


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """The model artifact URI a completed linear-learner CreateTrainingJob produces is the one
    referenced by the Model behind a subsequently created InService Endpoint, so artifact
    propagation is observed end to end."""
    registry_account = _ALGO_REGISTRY_ACCOUNTS.get(ctx.region)
    if registry_account is None:
        raise AssertionError(
            f"no known built-in-algorithm ECR registry account mapping for region "
            f"{ctx.region!r}; this check needs a real, pullable linear-learner image "
            f"to produce a genuine trained artifact"
        )
    image = f"{registry_account or '382416733822'}.dkr.ecr.{ctx.region}.amazonaws.com/linear-learner:1"

    role_arn = _create_sagemaker_role(ctx)
    sm = ctx.client("sagemaker")
    s3 = ctx.client("s3")

    # AmazonSageMakerFullAccess scopes its S3 permissions to buckets whose name
    # contains "sagemaker" (confirmed on real AWS: a bucket without it gets
    # AccessDenied on s3:GetObject during training data download).
    bucket_name = ctx.unique_name("sim2real-sagemaker-e2e-artifact-").replace("_", "-")
    _create_bucket(ctx, s3, bucket_name)

    train_key = "train/data.csv"
    csv_body = _synthetic_regression_csv(rows=40)
    s3.put_object(Bucket=bucket_name, Key=train_key, Body=csv_body.encode("utf-8"))

    job_name = ctx.unique_name("sim2real-e2e-train-")
    resource_tags = [{"Key": "sim2real-check", "Value": CHECK}]

    def _create_training_job():
        sm.create_training_job(
            TrainingJobName=job_name,
            AlgorithmSpecification={"TrainingImage": image, "TrainingInputMode": "File"},
            RoleArn=role_arn,
            HyperParameters={
                "feature_dim": "2",
                "predictor_type": "regressor",
                "mini_batch_size": "8",
                "epochs": "3",
            },
            InputDataConfig=[
                {
                    "ChannelName": "train",
                    "ContentType": "text/csv",
                    "CompressionType": "None",
                    "DataSource": {
                        "S3DataSource": {
                            "S3DataType": "S3Prefix",
                            "S3Uri": f"s3://{bucket_name}/train/",
                            "S3DataDistributionType": "FullyReplicated",
                        }
                    },
                }
            ],
            OutputDataConfig={"S3OutputPath": f"s3://{bucket_name}/output/"},
            ResourceConfig={"InstanceType": "ml.m5.large", "InstanceCount": 1, "VolumeSizeInGB": 10},
            StoppingCondition={"MaxRuntimeInSeconds": 1800},
            Tags=resource_tags,
        )

    # A just-created role's trust policy is not immediately assumable by SageMaker
    # everywhere; retry the first call that actually depends on that propagation
    # instead of sleeping blindly, bounded to a deadline.
    _retry_until_role_propagates(_create_training_job)

    def _stop_training_quiet():
        try:
            sm.stop_training_job(TrainingJobName=job_name)
        except ClientError as exc:
            # A job that is not InProgress refuses the stop with ValidationException; anything else fails.
            if exc.response["Error"]["Code"] != "ValidationException" or sm.describe_training_job(TrainingJobName=job_name)["TrainingJobStatus"] == "InProgress":
                raise

    ctx.on_cleanup(_stop_training_quiet)

    train_desc = _poll_until(
        lambda: sm.describe_training_job(TrainingJobName=job_name),
        lambda d: d["TrainingJobStatus"] in ("Completed", "Failed", "Stopped"),
        timeout_s=1800,
        interval_s=20,
    )
    assert train_desc["TrainingJobStatus"] == "Completed", (
        f"training job did not complete: {train_desc['TrainingJobStatus']} "
        f"({train_desc.get('FailureReason')})"
    )
    artifact_uri = train_desc["ModelArtifacts"]["S3ModelArtifacts"]
    assert artifact_uri.startswith(f"s3://{bucket_name}/"), (
        f"training job's own reported artifact {artifact_uri!r} is not inside "
        f"the bucket this check created ({bucket_name!r})"
    )

    model_name = ctx.unique_name("sim2real-e2e-model-")
    sm.create_model(
        ModelName=model_name,
        ExecutionRoleArn=role_arn,
        PrimaryContainer={"Image": image, "ModelDataUrl": artifact_uri},
        Tags=resource_tags,
    )
    ctx.on_cleanup(lambda: _delete_model_quiet(sm, model_name))

    model_desc = sm.describe_model(ModelName=model_name)
    assert model_desc["PrimaryContainer"]["ModelDataUrl"] == artifact_uri, (
        "Model does not reference the artifact produced by the completed training job: "
        f"{model_desc['PrimaryContainer']['ModelDataUrl']!r} != {artifact_uri!r}"
    )

    epc_name = ctx.unique_name("sim2real-e2e-epc-")
    sm.create_endpoint_config(
        EndpointConfigName=epc_name,
        ProductionVariants=[
            {
                "VariantName": "AllTraffic",
                "ModelName": model_name,
                "InitialInstanceCount": 1,
                "InstanceType": "ml.m5.large",
            }
        ],
        Tags=resource_tags,
    )
    ctx.on_cleanup(lambda: _delete_endpoint_config_quiet(sm, epc_name))

    ep_name = ctx.unique_name("sim2real-e2e-ep-")
    sm.create_endpoint(EndpointName=ep_name, EndpointConfigName=epc_name, Tags=resource_tags)
    ctx.on_cleanup(lambda: _delete_endpoint_quiet(sm, ep_name))

    ep_desc = _poll_until(
        lambda: sm.describe_endpoint(EndpointName=ep_name),
        lambda d: d["EndpointStatus"] in ("InService", "Failed"),
        timeout_s=900,
        interval_s=15,
    )
    assert ep_desc["EndpointStatus"] == "InService", (
        f"endpoint did not reach InService: {ep_desc['EndpointStatus']} "
        f"({ep_desc.get('FailureReason')})"
    )

    # Final propagation check: the endpoint that is actually InService is serving the
    # exact model that in turn references the exact artifact this training job produced.
    served_variant_name = ep_desc["ProductionVariants"][0]["VariantName"]
    assert served_variant_name == "AllTraffic", (
        f"InService endpoint {ep_name!r} is serving variant {served_variant_name!r}, "
        f"expected the single variant this check created: 'AllTraffic'"
    )
    epc_desc = sm.describe_endpoint_config(EndpointConfigName=epc_name)
    epc_model_name = epc_desc["ProductionVariants"][0]["ModelName"]
    assert epc_model_name == model_name, (
        f"endpoint config {epc_name!r} references model {epc_model_name!r}, "
        f"expected the model this check created: {model_name!r}"
    )
    served_artifact_uri = sm.describe_model(ModelName=model_name)["PrimaryContainer"]["ModelDataUrl"]
    assert served_artifact_uri == artifact_uri, (
        f"model {model_name!r} referenced by the InService endpoint's config points at "
        f"{served_artifact_uri!r}, not the artifact this training job actually produced: "
        f"{artifact_uri!r}"
    )


# ===== helpers =====
def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s, last value: {last}")


def _synthetic_regression_csv(rows: int) -> str:
    lines = []
    for i in range(rows):
        x1 = (i % 10) * 0.5
        x2 = ((i * 3) % 7) * 0.25
        label = 3.0 * x1 - 2.0 * x2 + 1.0
        lines.append(f"{label},{x1},{x2}")
    return "\n".join(lines) + "\n"


def _create_bucket(ctx, s3, bucket_name: str) -> None:
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket_name)
    else:
        s3.create_bucket(
            Bucket=bucket_name,
            CreateBucketConfiguration={"LocationConstraint": ctx.region},
        )
    s3.put_bucket_tagging(
        Bucket=bucket_name,
        Tagging={"TagSet": [{"Key": "sim2real-check", "Value": CHECK}]},
    )
    ctx.on_cleanup(lambda: _delete_bucket_quiet(s3, bucket_name))


def _delete_bucket_quiet(s3, bucket_name: str) -> None:
    try:
        objects = s3.list_objects_v2(Bucket=bucket_name).get("Contents", [])
        for obj in objects:
            s3.delete_object(Bucket=bucket_name, Key=obj["Key"])
        s3.delete_bucket(Bucket=bucket_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchBucket":
            raise


def _is_gone(exc) -> bool:
    """SageMaker reports a missing model, endpoint config or endpoint as ValidationException "Could not find"."""
    error = exc.response["Error"]
    return error["Code"] == "ValidationException" and "Could not find" in error.get("Message", "")


def _delete_model_quiet(sm, model_name: str) -> None:
    try:
        sm.delete_model(ModelName=model_name)
    except ClientError as exc:
        if not _is_gone(exc):
            raise


def _delete_endpoint_config_quiet(sm, epc_name: str) -> None:
    try:
        sm.delete_endpoint_config(EndpointConfigName=epc_name)
    except ClientError as exc:
        if not _is_gone(exc):
            raise


def _delete_endpoint_quiet(sm, ep_name: str) -> None:
    # A still-Creating endpoint refuses the delete with ValidationException: retried for 600 s.
    deadline = time.monotonic() + 600
    while True:
        try:
            sm.delete_endpoint(EndpointName=ep_name)
            break
        except ClientError as exc:
            if _is_gone(exc):
                break
            if exc.response["Error"]["Code"] != "ValidationException":
                raise
            if time.monotonic() >= deadline:
                raise
        time.sleep(2)
    deadline = time.monotonic() + 300
    while True:
        try:
            sm.describe_endpoint(EndpointName=ep_name)
        except ClientError as exc:
            if _is_gone(exc):
                return
            raise
        if time.monotonic() >= deadline:
            raise TimeoutError(f"endpoint {ep_name} still describable 300s after DeleteEndpoint")
        time.sleep(2)


def _create_sagemaker_role(ctx):
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-e2e-role-")
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
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )["Role"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    policy_arn = "arn:aws:iam::aws:policy/AmazonSageMakerFullAccess"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=policy_arn))
    return role["Arn"]


def _retry_until_role_propagates(fn, *, timeout_s: float = 90.0, interval_s: float = 5.0) -> None:
    """A just-attached IAM trust policy is not instantly assumable by SageMaker
    everywhere; retry the dependent call until it stops rejecting the role or the
    deadline passes, then surface whatever error it last raised."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            fn()
            return
        except ClientError:
            if time.monotonic() >= deadline:
                raise
            time.sleep(interval_s)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
