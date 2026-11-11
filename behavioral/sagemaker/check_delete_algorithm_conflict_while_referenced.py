"""delete-algorithm-conflict-while-referenced."""
from __future__ import annotations

import time
from typing import Any

from behavioral_harness import tags

CHECK = "delete-algorithm-conflict-while-referenced"
GROUP = "error-semantics"
SERVICES = ["sagemaker"]

# Registry account IDs for the SageMaker 1P built-in-algorithm ECR images. These images
# are publicly readable cross-account, so they let CreateAlgorithm's real "does this
# TrainingImage actually resolve" check succeed without us owning a private ECR repo.
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


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DeleteAlgorithm succeeds while a ModelPackage still references the algorithm: the algorithm
    leaves lookups, and the package stays describable, still naming the deleted algorithm."""
    account_id = _BUILTIN_ALGO_REGISTRY.get(ctx.region)
    if account_id is None:
        raise AssertionError(
            f"region {ctx.region} is not in the curated built-in-algorithm ECR registry "
            "map used by this check to source a real, resolvable training image"
        )
    training_spec = _minimal_training_spec(ctx, account_id)
    inference_spec = _minimal_inference_spec(ctx, account_id)

    sm = ctx.client("sagemaker")
    bucket, key = _create_model_artifact(ctx)

    algo_name = ctx.unique_name("sim2real-behav-algo-")
    sm.create_algorithm(
        AlgorithmName=algo_name,
        TrainingSpecification=training_spec,
        InferenceSpecification=inference_spec,
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: _safe_delete_algorithm(sm, algo_name))
    _wait_for_algorithm_completed(sm, algo_name)

    package_name = ctx.unique_name("sim2real-behav-mp-")
    sm.create_model_package(
        ModelPackageName=package_name,
        SourceAlgorithmSpecification={
            "SourceAlgorithms": [
                {"AlgorithmName": algo_name, "ModelDataUrl": f"s3://{bucket}/{key}"}
            ]
        },
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: _safe_delete_model_package(sm, package_name))

    # SourceAlgorithmSpecification is a copy taken at package creation, not a delete-blocking link.
    sm.delete_algorithm(AlgorithmName=algo_name)

    gone_code, gone_message = _error_code_and_message(
        lambda: sm.describe_algorithm(AlgorithmName=algo_name)
    )
    # DescribeAlgorithm on a gone algorithm surfaces as ValidationException rather than
    # the generic ResourceNotFound used elsewhere in SageMaker.
    assert gone_code == "ValidationException", (
        f"expected the deleted algorithm {algo_name!r} lookup to fail with "
        f"ValidationException, got {gone_code}: {gone_message!r}"
    )
    expected_gone = f"Algorithm arn:aws:sagemaker:{ctx.region}:{ctx.account}:algorithm/{algo_name} does not exist."
    assert gone_message == expected_gone, (
        f"expected the deleted-algorithm refusal {expected_gone!r}, got {gone_message!r}"
    )

    mp_described = sm.describe_model_package(ModelPackageName=package_name)
    assert mp_described["ModelPackageName"] == package_name, (
        f"expected the referencing model package {package_name!r} to remain describable "
        f"after the algorithm it named was deleted, got {mp_described.get('ModelPackageName')!r}"
    )
    referenced_name = mp_described["SourceAlgorithmSpecification"]["SourceAlgorithms"][0]["AlgorithmName"]
    assert referenced_name == algo_name, (
        f"expected the model package's stored SourceAlgorithmSpecification to still name "
        f"{algo_name!r}, got {referenced_name!r}"
    )


def _minimal_training_spec(ctx: Any, account_id: str) -> dict:
    return {
        "TrainingImage": f"{account_id}.dkr.ecr.{ctx.region}.amazonaws.com/knn:1",
        "SupportedTrainingInstanceTypes": ["ml.m5.large"],
        "TrainingChannels": [
            {
                "Name": "training",
                "SupportedContentTypes": ["text/csv"],
                "SupportedInputModes": ["File"],
            }
        ],
    }


def _minimal_inference_spec(ctx: Any, account_id: str) -> dict:
    return {
        "Containers": [{"Image": f"{account_id}.dkr.ecr.{ctx.region}.amazonaws.com/knn:1"}],
        "SupportedContentTypes": ["text/csv"],
        "SupportedResponseMIMETypes": ["text/csv"],
        "SupportedRealtimeInferenceInstanceTypes": ["ml.m5.large"],
        "SupportedTransformInstanceTypes": ["ml.m5.large"],
    }


def _create_model_artifact(ctx) -> tuple[str, str]:
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-behav-algo-mp-").lower().replace("_", "-")
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(
            Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region}
        )
    ctx.on_cleanup(lambda: s3.delete_bucket(Bucket=bucket))
    key = "model.tar.gz"
    s3.put_object(Bucket=bucket, Key=key, Body=b"sim2real-placeholder-model-artifact")
    ctx.on_cleanup(lambda: s3.delete_object(Bucket=bucket, Key=key))
    return bucket, key


def _wait_for_algorithm_completed(sm, algo_name: str, *, timeout_s: float = 180.0, interval_s: float = 5.0) -> None:
    deadline = time.monotonic() + timeout_s
    last_status = None
    while time.monotonic() < deadline:
        described = sm.describe_algorithm(AlgorithmName=algo_name)
        last_status = described["AlgorithmStatus"]
        if last_status == "Completed":
            return
        if last_status == "Failed":
            raise AssertionError(
                f"algorithm {algo_name} failed validation: {described.get('AlgorithmStatusDetails')}"
            )
        time.sleep(interval_s)
    raise AssertionError(
        f"algorithm {algo_name} never reached Completed within {timeout_s}s (last status: {last_status})"
    )


def _error_code_and_message(fn):
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(
        f"expected the call to be rejected, but it succeeded and returned {result!r}"
    )


def _safe_delete_model_package(sm, name: str) -> None:
    from botocore.exceptions import ClientError

    try:
        sm.delete_model_package(ModelPackageName=name)
    except ClientError as exc:
        error = exc.response["Error"]
        if error["Code"] != "ValidationException" or "does not exist" not in error.get("Message", ""):
            raise


def _safe_delete_algorithm(sm, name: str) -> None:
    from botocore.exceptions import ClientError

    try:
        sm.delete_algorithm(AlgorithmName=name)
    except ClientError as exc:
        error = exc.response["Error"]
        if error["Code"] != "ValidationException" or "does not exist" not in error.get("Message", ""):
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
