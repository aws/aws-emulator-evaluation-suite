"""deploy-endpoint-cfn-then-invoke-succeeds."""
from __future__ import annotations

import json
import math
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-endpoint-cfn-then-invoke-succeeds"
GROUP = "deploy"
SERVICES = ["sagemaker"]

# Built-in "linear-learner" algorithm image account IDs, stable across years, one per
# region. See https://docs.aws.amazon.com/sagemaker/latest/dg/linear-learner.html
_LINEAR_LEARNER_ACCOUNTS = {
    "us-east-1": "382416733822",
    "us-east-2": "404615174143",
    "us-west-1": "632365934929",
    "us-west-2": "174872318107",
    "eu-west-1": "438346466558",
    "eu-central-1": "664544806723",
    "eu-north-1": "669576153137",
    "eu-west-2": "644912444149",
    "ap-northeast-1": "351501993468",
    "ap-northeast-2": "835164637446",
    "ap-southeast-1": "121021644041",
    "ap-southeast-2": "783357654285",
    "ap-south-1": "991648021394",
    "sa-east-1": "855470959533",
    "ca-central-1": "469771592824",
}

_ENDPOINT_STACK_TEMPLATE = """
AWSTemplateFormatVersion: '2010-09-09'
Parameters:
  ModelName:
    Type: String
  EndpointConfigName:
    Type: String
  EndpointName:
    Type: String
  ExecutionRoleArn:
    Type: String
  Image:
    Type: String
  ModelDataUrl:
    Type: String
Resources:
  Model:
    Type: AWS::SageMaker::Model
    Properties:
      ModelName: !Ref ModelName
      ExecutionRoleArn: !Ref ExecutionRoleArn
      PrimaryContainer:
        Image: !Ref Image
        ModelDataUrl: !Ref ModelDataUrl
  EndpointConfig:
    Type: AWS::SageMaker::EndpointConfig
    DependsOn: Model
    Properties:
      EndpointConfigName: !Ref EndpointConfigName
      ProductionVariants:
        - VariantName: AllTraffic
          ModelName: !Ref ModelName
          InitialInstanceCount: 1
          InstanceType: ml.m5.large
  Endpoint:
    Type: AWS::SageMaker::Endpoint
    DependsOn: EndpointConfig
    Properties:
      EndpointName: !Ref EndpointName
      EndpointConfigName: !Ref EndpointConfigName
""".strip()


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "concern:deploy", "dp:api", "plane:data")
def run(ctx) -> None:
    """A CloudFormation Model+EndpointConfig+Endpoint stack reaches CREATE_COMPLETE with the
    endpoint InService, and the endpoint's prediction lands near the true value of its
    noise-free linear training function, not merely a finite number."""
    image_uri = _linear_learner_image(ctx)
    if image_uri is None:
        raise AssertionError(
            f"no known built-in linear-learner registry account mapped for region "
            f"{ctx.region!r}; would need the SageMaker Python SDK's image_uris.retrieve "
            "to resolve this dynamically"
        )

    sm = ctx.client("sagemaker")
    cfn = ctx.client("cloudformation")
    role_arn = _create_sagemaker_role(ctx)
    bucket = _create_bucket(ctx)
    _upload_training_csv(ctx, bucket)

    job_name = ctx.unique_name("sim2real-sm-train-")
    _retry_role_propagation(
        lambda: sm.create_training_job(
            TrainingJobName=job_name,
            AlgorithmSpecification={"TrainingImage": image_uri, "TrainingInputMode": "File"},
            RoleArn=role_arn,
            InputDataConfig=[
                {
                    "ChannelName": "train",
                    "DataSource": {
                        "S3DataSource": {
                            "S3DataType": "S3Prefix",
                            "S3Uri": f"s3://{bucket}/train/",
                            "S3DataDistributionType": "FullyReplicated",
                        }
                    },
                    "ContentType": "text/csv",
                }
            ],
            OutputDataConfig={"S3OutputPath": f"s3://{bucket}/output/"},
            ResourceConfig={"InstanceType": "ml.m5.large", "InstanceCount": 1, "VolumeSizeInGB": 5},
            StoppingCondition={"MaxRuntimeInSeconds": 900},
            HyperParameters={
                "feature_dim": "2",
                "predictor_type": "regressor",
                "mini_batch_size": "10",
            },
            Tags=[{"Key": "sim2real", "Value": CHECK}],
        )
    )
    ctx.on_cleanup(lambda: _safe_delete_training_job(sm, job_name))

    train_desc = _wait_training_job(sm, job_name, timeout_s=_budget_s(ctx, 1200.0), ctx=ctx)
    assert train_desc["TrainingJobStatus"] == "Completed", train_desc.get("FailureReason")
    model_data_url = train_desc["ModelArtifacts"]["S3ModelArtifacts"]

    model_name = ctx.unique_name("sim2real-sm-model-")
    config_name = ctx.unique_name("sim2real-sm-epc-")
    endpoint_name = ctx.unique_name("sim2real-sm-ep-")
    stack_name = ctx.unique_name("sim2real-sm-ep-stack-")

    cfn.create_stack(
        StackName=stack_name,
        TemplateBody=_ENDPOINT_STACK_TEMPLATE,
        Parameters=[
            {"ParameterKey": "ModelName", "ParameterValue": model_name},
            {"ParameterKey": "EndpointConfigName", "ParameterValue": config_name},
            {"ParameterKey": "EndpointName", "ParameterValue": endpoint_name},
            {"ParameterKey": "ExecutionRoleArn", "ParameterValue": role_arn},
            {"ParameterKey": "Image", "ParameterValue": image_uri},
            {"ParameterKey": "ModelDataUrl", "ParameterValue": model_data_url},
        ],
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: cfn.delete_stack(StackName=stack_name))

    _wait_stack_create(cfn, stack_name, timeout_s=_budget_s(ctx, 1200.0), ctx=ctx)

    desc = sm.describe_endpoint(EndpointName=endpoint_name)
    assert desc["EndpointStatus"] == "InService", desc["EndpointStatus"]

    rt = ctx.client("sagemaker-runtime")
    query_x1, query_x2 = 5.0, 3.0
    resp = rt.invoke_endpoint(
        EndpointName=endpoint_name,
        ContentType="text/csv",
        Accept="application/json",
        Body=f"{query_x1},{query_x2}\n".encode("utf-8"),
    )
    payload = json.loads(resp["Body"].read())
    predictions = payload["predictions"]
    assert len(predictions) == 1
    score = predictions[0]["score"]
    assert isinstance(score, (int, float))
    assert math.isfinite(score)
    expected = _true_label(query_x1, query_x2)
    assert abs(score - expected) < 10.0, (
        f"endpoint trained on a noise-free label = 3*x1 + 2*x2 + 1 predicted {score!r} "
        f"for (x1={query_x1}, x2={query_x2}); expected something near {expected}"
    )



_SAGEMAKER_TRUST_POLICY = json.dumps(
    {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "sagemaker.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
)


def _linear_learner_image(ctx) -> str | None:
    account = _LINEAR_LEARNER_ACCOUNTS.get(ctx.region)
    if not account:
        return None
    return f"{account}.dkr.ecr.{ctx.region}.amazonaws.com/linear-learner:1"


def _retry_role_propagation(fn, timeout_s: float = 60.0, interval_s: float = 2.0):
    """IAM role/trust-policy propagation to SageMaker is eventually consistent; retry
    the actual call that needs the role rather than guessing a fixed grace period."""
    deadline = time.monotonic() + timeout_s
    last_exc = None
    while time.monotonic() < deadline:
        try:
            return fn()
        except ClientError as exc:
            last_exc = exc
            code = exc.response.get("Error", {}).get("Code", "")
            if code in ("AccessDeniedException", "ValidationException"):
                time.sleep(interval_s)
                continue
            raise
    raise last_exc


def _create_sagemaker_role(ctx) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-sm-role-")
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=_SAGEMAKER_TRUST_POLICY,
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]
    policy_arn = "arn:aws:iam::aws:policy/AmazonSageMakerFullAccess"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)

    def _cleanup() -> None:
        for delete in (
            lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=policy_arn),
            lambda: iam.delete_role(RoleName=role_name),
        ):
            try:
                delete()
            except ClientError as e:
                if e.response["Error"]["Code"] != "NoSuchEntity":
                    raise

    ctx.on_cleanup(_cleanup)

    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        try:
            iam.get_role(RoleName=role_name)
            break
        except Exception:
            time.sleep(2)
    return role["Arn"]


def _create_bucket(ctx) -> str:
    s3 = ctx.client("s3")
    # AmazonSageMakerFullAccess's S3 grant is conditioned on the bucket name containing
    # "sagemaker" -- a plain "sim2real-sm-*" name is denied s3:GetObject/PutObject.
    bucket = ctx.unique_name("sim2real-sagemaker-").lower().replace("_", "-")
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(
            Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region}
        )
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [{"Key": "sim2real", "Value": CHECK}]})

    def _cleanup() -> None:
        try:
            objs = s3.list_objects_v2(Bucket=bucket).get("Contents", [])
            for obj in objs:
                s3.delete_object(Bucket=bucket, Key=obj["Key"])
            s3.delete_bucket(Bucket=bucket)
        except ClientError as e:
            if e.response["Error"]["Code"] != "NoSuchBucket":
                raise

    ctx.on_cleanup(_cleanup)
    return bucket


def _true_label(x1: float, x2: float) -> float:
    """The noise-free linear function the training CSV is generated from."""
    return 3.0 * x1 + 2.0 * x2 + 1.0


def _upload_training_csv(ctx, bucket: str) -> None:
    s3 = ctx.client("s3")
    lines = []
    for i in range(50):
        x1 = float(i % 10)
        x2 = float((i * 3) % 7)
        lines.append(f"{_true_label(x1, x2)},{x1},{x2}")
    body = ("\n".join(lines) + "\n").encode("utf-8")
    s3.put_object(Bucket=bucket, Key="train/train.csv", Body=body)


_POLL_INTERVAL_S = 2.0


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _wait_training_job(sm, job_name: str, timeout_s: float = 1200.0, ctx=None) -> dict:
    deadline = time.monotonic() + timeout_s
    while True:
        desc = sm.describe_training_job(TrainingJobName=job_name)
        status = desc["TrainingJobStatus"]
        if status in ("Completed", "Failed", "Stopped"):
            return desc
        if time.monotonic() >= deadline:
            if ctx is not None and _budget_spent(ctx):
                raise TimeoutError(f"training job {job_name} to finish: the run budget ended first; not graded")
            raise AssertionError(f"training job {job_name} did not finish within {timeout_s:.0f}s: {desc}")
        time.sleep(_POLL_INTERVAL_S)


def _safe_delete_training_job(sm, job_name: str) -> None:
    try:
        desc = sm.describe_training_job(TrainingJobName=job_name)
    except ClientError as e:
        error = e.response["Error"]
        if error["Code"] == "ResourceNotFound" or "not found" in error.get("Message", "").lower():
            return
        raise
    if desc["TrainingJobStatus"] not in ("Completed", "Failed", "Stopped"):
        try:
            sm.stop_training_job(TrainingJobName=job_name)
        except ClientError as exc:
            # A job that is not InProgress refuses the stop with ValidationException; anything else fails.
            if exc.response["Error"]["Code"] != "ValidationException" or sm.describe_training_job(TrainingJobName=job_name)["TrainingJobStatus"] == "InProgress":
                raise
        _wait_training_job(sm, job_name, timeout_s=300)
    try:
        sm.delete_training_job(TrainingJobName=job_name)
    except ClientError as e:
        if e.response["Error"]["Code"] != "ResourceNotFound":
            raise


def _stack_failure_reasons(cfn, stack_name: str) -> str:
    events = cfn.describe_stack_events(StackName=stack_name)["StackEvents"]
    failed = [e for e in events if e["ResourceStatus"].endswith("FAILED")]
    return "; ".join(
        f"{e['LogicalResourceId']}: {e.get('ResourceStatusReason', '(no reason)')}" for e in failed
    )


def _wait_stack_create(cfn, stack_name: str, timeout_s: float = 900.0, ctx=None) -> None:
    deadline = time.monotonic() + timeout_s
    while True:
        status = cfn.describe_stacks(StackName=stack_name)["Stacks"][0]["StackStatus"]
        if status == "CREATE_COMPLETE":
            return
        if status not in ("CREATE_IN_PROGRESS", "REVIEW_IN_PROGRESS"):
            raise AssertionError(
                f"stack {stack_name} entered unexpected status {status}: "
                f"{_stack_failure_reasons(cfn, stack_name)}"
            )
        if time.monotonic() >= deadline:
            if ctx is not None and _budget_spent(ctx):
                raise TimeoutError(f"stack {stack_name} to reach CREATE_COMPLETE: the run budget ended first; not graded")
            raise AssertionError(
                f"stack {stack_name} did not reach CREATE_COMPLETE within {timeout_s:.0f}s (last={status})"
            )
        time.sleep(_POLL_INTERVAL_S)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
