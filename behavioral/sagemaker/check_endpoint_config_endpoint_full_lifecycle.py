"""endpoint-config-endpoint-full-lifecycle."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "endpoint-config-endpoint-full-lifecycle"
GROUP = "state-machine"
SERVICES = ["sagemaker"]

# Registry account IDs for the SageMaker 1P built-in-algorithm ECR images (used here for the
# "knn" image, which supports MultiModel mode and does NOT preload any model at container
# startup -- it lazily loads a model only on the first invoke that targets it). That lets us
# reach a real InService endpoint without needing to train and upload an actual model artifact.
_BUILTIN_ALGO_REGISTRY = {
    "us-east-1": "382416733822",
    "us-east-2": "404615174143",
    "us-west-1": "632365934929",
    "us-west-2": "174872318107",
    "ap-northeast-1": "351501993468",
    "ap-northeast-2": "835164637446",
    "ap-south-1": "991648021394",
    "ap-southeast-1": "475088953585",
    "ap-southeast-2": "712309505854",
    "ca-central-1": "469771592824",
    "eu-central-1": "664544806723",
    "eu-north-1": "669576153137",
    "eu-west-1": "438346466558",
    "eu-west-2": "644912444149",
    "eu-west-3": "749696950732",
    "sa-east-1": "855470959533",
}


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Endpoint moves Creating->InService; DeleteEndpoint/DeleteEndpointConfig fully remove it."""
    account_id = _BUILTIN_ALGO_REGISTRY.get(ctx.region)
    if account_id is None:
        raise AssertionError(
            f"region {ctx.region} is not in the curated built-in-algorithm ECR registry "
            "map used by this check to source a real inference container"
        )

    sm = ctx.client("sagemaker")
    iam = ctx.client("iam")
    s3 = ctx.client("s3")

    role_arn = _create_sagemaker_execution_role(ctx, iam)
    bucket = _create_model_data_bucket(ctx, s3)

    model_name = ctx.unique_name("sim2real-behav-epmodel-")
    config_name = ctx.unique_name("sim2real-behav-epcfg-")
    endpoint_name = ctx.unique_name("sim2real-behav-ep-")

    image = f"{account_id}.dkr.ecr.{ctx.region}.amazonaws.com/knn:1"
    _retry_role_propagation(
        lambda: sm.create_model(
            ModelName=model_name,
            ExecutionRoleArn=role_arn,
            Containers=[
                {
                    "Image": image,
                    "ModelDataUrl": f"s3://{bucket}/models/",
                    "Mode": "MultiModel",
                }
            ],
            Tags=[{"Key": "sim2real-check", "Value": CHECK}],
        )
    )
    ctx.on_cleanup(lambda: _delete_model_quiet(sm, model_name))

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
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: _delete_endpoint_config_quiet(sm, config_name))

    sm.create_endpoint(
        EndpointName=endpoint_name,
        EndpointConfigName=config_name,
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: _delete_endpoint_quiet(sm, endpoint_name))

    status, failure_reason = _poll_endpoint_status(
        sm, endpoint_name, {"InService", "Failed"}, timeout_s=600.0
    )
    assert status == "InService", f"endpoint did not reach InService: {failure_reason}"

    sm.delete_endpoint(EndpointName=endpoint_name)
    gone_code, gone_message = _poll_until_endpoint_gone(sm, endpoint_name, timeout_s=180.0)
    assert gone_code == "ValidationException", (
        f"expected ValidationException describing deleted endpoint {endpoint_name}, got {gone_code!r}"
    )
    expected = f'Could not find endpoint "{endpoint_name}".'
    assert gone_message == expected, f"expected message {expected!r}, got {gone_message!r}"

    sm.delete_endpoint_config(EndpointConfigName=config_name)
    code, message = _error(lambda: sm.describe_endpoint_config(EndpointConfigName=config_name))
    assert code == "ValidationException", (
        f"expected ValidationException describing deleted endpoint config {config_name}, got {code!r}"
    )
    expected = f'Could not find endpoint configuration "{config_name}".'
    assert message == expected, f"expected message {expected!r}, got {message!r}"


def _error(fn):
    """Call fn(); return its (code, message). A success raises: the call must be refused."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _create_sagemaker_execution_role(ctx, iam) -> str:
    role_name = ctx.unique_name("sim2real-behav-sm-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "sagemaker.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    resp = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )
    role_arn = resp["Role"]["Arn"]
    policy_arns = (
        "arn:aws:iam::aws:policy/AmazonSageMakerFullAccess",
        "arn:aws:iam::aws:policy/AmazonS3FullAccess",
    )
    for policy_arn in policy_arns:
        iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)

    def _cleanup():
        for policy_arn in policy_arns:
            try:
                iam.detach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "NoSuchEntity":
                    raise
        try:
            iam.delete_role(RoleName=role_name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise

    ctx.on_cleanup(_cleanup)
    return role_arn


def _create_model_data_bucket(ctx, s3) -> str:
    bucket = ctx.unique_name("sim2real-behav-sm-mme-").lower().replace("_", "-")
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region})
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [{"Key": "sim2real-check", "Value": CHECK}]})
    # CreateModel validates the ExecutionRole can list/read at ModelDataUrl even for a
    # MultiModel endpoint that lazily loads models on first invoke -- the prefix must exist.
    s3.put_object(Bucket=bucket, Key="models/.keep", Body=b"")

    def _cleanup():
        try:
            paginator = s3.get_paginator("list_objects_v2")
            for page in paginator.paginate(Bucket=bucket):
                for obj in page.get("Contents", []):
                    s3.delete_object(Bucket=bucket, Key=obj["Key"])
            s3.delete_bucket(Bucket=bucket)
        except ClientError as exc:
            if exc.response["Error"]["Code"] not in ("NoSuchBucket", "NoSuchKey"):
                raise

    ctx.on_cleanup(_cleanup)
    return bucket


def _delete_model_quiet(sm, name: str) -> None:
    try:
        sm.delete_model(ModelName=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFound":
            raise


def _delete_endpoint_config_quiet(sm, name: str) -> None:
    try:
        sm.delete_endpoint_config(EndpointConfigName=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFound":
            raise


def _delete_endpoint_quiet(sm, name: str) -> None:
    try:
        sm.delete_endpoint(EndpointName=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFound":
            raise


def _poll_endpoint_status(sm, endpoint_name, terminal_statuses, timeout_s=600.0, interval_s=15.0):
    deadline = time.monotonic() + timeout_s
    status = None
    failure_reason = None
    while time.monotonic() < deadline:
        described = sm.describe_endpoint(EndpointName=endpoint_name)
        status = described["EndpointStatus"]
        failure_reason = described.get("FailureReason")
        if status in terminal_statuses:
            return status, failure_reason
        time.sleep(interval_s)
    raise AssertionError(
        f"endpoint {endpoint_name} did not reach a terminal status within {timeout_s}s "
        f"(last observed status={status!r})"
    )


def _poll_until_endpoint_gone(sm, endpoint_name, timeout_s=180.0, interval_s=10.0):
    """Poll DescribeEndpoint until it is refused; return the refusal's (code, message). An
    endpoint still describable at the deadline raises."""
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            sm.describe_endpoint(EndpointName=endpoint_name)
        except ClientError as exc:
            err = exc.response.get("Error", {})
            return err.get("Code"), err.get("Message")
        time.sleep(interval_s)
    raise AssertionError(f"endpoint {endpoint_name} was not deleted within {timeout_s}s")


def _retry_role_propagation(fn, timeout_s: float = 90.0, interval_s: float = 10.0):
    """IAM role trust propagation to the SageMaker control plane can lag by tens of seconds;
    retry the specific role-not-yet-assumable error within a bounded window rather than a
    fixed sleep before the one real attempt.
    """
    deadline = time.monotonic() + timeout_s
    last_exc = None
    while time.monotonic() < deadline:
        try:
            return fn()
        except Exception as exc:  # noqa: BLE001
            code = getattr(exc, "response", {}).get("Error", {}).get("Code")
            message = getattr(exc, "response", {}).get("Error", {}).get("Message", "")
            if code == "ValidationException" and "role" in message.lower():
                last_exc = exc
                time.sleep(interval_s)
                continue
            raise
    raise last_exc


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
