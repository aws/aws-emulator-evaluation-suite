"""sagemaker-endpoint-config-model-data-url-resolution."""
from __future__ import annotations

import json
import time
from typing import Any

from behavioral_harness import tags

CHECK = "sagemaker-endpoint-config-model-data-url-resolution"
GROUP = "arn-resolution"
SERVICES = ["s3", "sagemaker"]

# The SageMaker XGBoost framework container is published to a distinct ECR account per
# region (AWS's fixed registry convention, not derivable from any API call) -- resolved
# via the sagemaker SDK when available, else this table.
_XGBOOST_IMAGES = {
    "us-east-1": "683313688378.dkr.ecr.us-east-1.amazonaws.com/sagemaker-xgboost:1.7-1",
    "us-west-2": "246618743249.dkr.ecr.us-west-2.amazonaws.com/sagemaker-xgboost:1.7-1",
}


def _resolve_xgboost_image(ctx: Any) -> str:
    try:
        from sagemaker.core.image_uris import retrieve  # type: ignore

        return retrieve("xgboost", ctx.region, version="1.7-1")
    except Exception:
        pass
    image = _XGBOOST_IMAGES.get(ctx.region)
    if image is None:
        raise AssertionError(
            f"no verified built-in XGBoost image mapping maintained for region {ctx.region}; "
            "add an entry to _XGBOOST_IMAGES to close this gap for other regions."
        )
    return image


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "concern:e2e", "dp:api", "plane:data")
def run(ctx: Any) -> None:
    """A trained XGBoost model deployed through an EndpointConfig reaches InService under that config, and
    live inference returns probabilities in [0, 1] whose high-input score exceeds the low-input score by
    more than 0.2, so the weights were fetched from the model's S3 ModelDataUrl."""
    image = _resolve_xgboost_image(ctx)

    s3 = ctx.client("s3")
    sm = ctx.client("sagemaker")
    smrt = ctx.client("sagemaker-runtime")

    bucket = _create_bucket(ctx)
    role = _create_role(ctx, bucket)

    train_key = "train/train.csv"
    s3.put_object(Bucket=bucket, Key=train_key, Body=_xgboost_training_csv().encode("utf-8"))

    job_name = ctx.unique_name("sim2real-sm-train-")
    _create_training_job_with_role_propagation_retry(
        sm,
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
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )

    train_desc = _poll_until(
        lambda: sm.describe_training_job(TrainingJobName=job_name),
        lambda d: d["TrainingJobStatus"] in ("Completed", "Failed", "Stopped"),
        timeout_s=900,
        interval_s=20,
    )
    assert train_desc["TrainingJobStatus"] == "Completed", (
        f"expected Completed, got {train_desc['TrainingJobStatus']} ({train_desc.get('FailureReason')})"
    )
    model_data_url = train_desc["ModelArtifacts"]["S3ModelArtifacts"]

    model_name = ctx.unique_name("sim2real-sm-model-")
    sm.create_model(
        ModelName=model_name,
        PrimaryContainer={"Image": image, "ModelDataUrl": model_data_url},
        ExecutionRoleArn=role["arn"],
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: sm.delete_model(ModelName=model_name))

    endpoint_config_name = ctx.unique_name("sim2real-sm-epc-")
    sm.create_endpoint_config(
        EndpointConfigName=endpoint_config_name,
        ProductionVariants=[{
            "VariantName": "AllTraffic",
            "ModelName": model_name,
            "InitialInstanceCount": 1,
            "InstanceType": "ml.m5.large",
        }],
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: sm.delete_endpoint_config(EndpointConfigName=endpoint_config_name))

    endpoint_name = ctx.unique_name("sim2real-sm-ep-")
    sm.create_endpoint(
        EndpointName=endpoint_name,
        EndpointConfigName=endpoint_config_name,
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: sm.delete_endpoint(EndpointName=endpoint_name))

    ep_desc = _poll_until(
        lambda: sm.describe_endpoint(EndpointName=endpoint_name),
        lambda d: d["EndpointStatus"] in ("InService", "Failed"),
        timeout_s=900,
        interval_s=20,
    )
    assert ep_desc["EndpointStatus"] == "InService", (
        f"expected InService, got {ep_desc['EndpointStatus']} ({ep_desc.get('FailureReason')})"
    )
    # DescribeEndpoint reports the resolved model/config, proving the variant->model->S3 chain.
    assert ep_desc["EndpointConfigName"] == endpoint_config_name, (
        f"expected {endpoint_config_name}, got {ep_desc['EndpointConfigName']}"
    )

    # The training rows encode label via a fixed offset: label=0 features sit in [0, 1],
    # label=1 features sit in [3, 4] -- a trivially separable pattern. Probing both regions
    # and requiring the real model to separate them is proof the container loaded the real
    # weights fetched from the S3 ModelDataUrl: a canned/stubbed response returns the same
    # (or an unordered) value for both, and a bounds-only check would pass either way.
    resp_low = smrt.invoke_endpoint(EndpointName=endpoint_name, ContentType="text/csv", Body="0.9,0.9")
    resp_high = smrt.invoke_endpoint(EndpointName=endpoint_name, ContentType="text/csv", Body="3.9,3.9")
    prob_low = float(resp_low["Body"].read().decode("utf-8").strip())
    prob_high = float(resp_high["Body"].read().decode("utf-8").strip())
    assert 0.0 <= prob_low <= 1.0, f"predicted probability out of range: {prob_low}"
    assert 0.0 <= prob_high <= 1.0, f"predicted probability out of range: {prob_high}"
    assert prob_high > prob_low + 0.2, (
        f"model failed to separate the two label regions it was trained on: "
        f"P(label=1 | near label-0 input)={prob_low}, P(label=1 | near label-1 input)={prob_high}"
    )


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


def _poll_until(probe, predicate, timeout_s: float = 600.0, interval_s: float = 15.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last value={last}")


def _create_training_job_with_role_propagation_retry(
    sm: Any, timeout_s: float = 120.0, interval_s: float = 10.0, **kwargs: Any
) -> dict:
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return sm.create_training_job(**kwargs)
        except ClientError as e:
            code = e.response["Error"]["Code"]
            msg = e.response["Error"].get("Message", "").lower()
            role_not_yet_propagated = "trust" in msg or "assume role" in msg or "not authorized" in msg
            if code == "ValidationException" and role_not_yet_propagated and time.monotonic() < deadline:
                time.sleep(interval_s)
                continue
            raise


def _create_bucket(ctx: Any) -> str:
    s3 = ctx.client("s3")
    name = ctx.unique_name("sim2real-sm-s3-").lower()
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=name)
    else:
        s3.create_bucket(Bucket=name, CreateBucketConfiguration={"LocationConstraint": ctx.region})
    s3.put_bucket_tagging(Bucket=name, Tagging={"TagSet": [{"Key": "sim2real", "Value": CHECK}]})

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
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    role_arn = role["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    policy_arn = "arn:aws:iam::aws:policy/AmazonSageMakerFullAccess"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=policy_arn))
    # AmazonSageMakerFullAccess's own S3 grant only matches bucket names containing
    # "sagemaker"/"Sagemaker"/"SageMaker" -- this check's bucket does not, so the
    # training job's GetObject on the uploaded CSV is denied without an explicit
    # bucket-scoped grant (confirmed on real AWS: AccessDenied on s3:GetObject).
    policy_name = ctx.unique_name("sim2real-sm-s3policy-")
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName=policy_name,
        PolicyDocument=json.dumps({
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Action": ["s3:GetObject", "s3:PutObject", "s3:ListBucket"],
                "Resource": [f"arn:aws:s3:::{bucket}", f"arn:aws:s3:::{bucket}/*"],
            }],
        }),
    )
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name))
    # IAM role/policy propagation is bounded by _create_training_job_with_role_propagation_retry,
    # which is the first call that actually needs the role to be assumable.
    return {"arn": role_arn, "name": role_name}


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
