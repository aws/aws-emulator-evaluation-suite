"""delete-algorithm-in-use-conflict."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-algorithm-in-use-conflict"
GROUP = "error-semantics"
SERVICES = ["sagemaker"]

# SageMaker's own built-in-algorithm ECR images are publicly pullable by any
# account, so referencing one (instead of a made-up image URI in a fake
# account) lets CreateAlgorithm's registry-access check succeed without us
# needing to push a real image. Account IDs are the well-known "1P
# algorithms" registry per Region (kmeans/pca/linear-learner family).
_BUILTIN_ALGO_ACCOUNT_BY_REGION = {
    "us-east-1": "382416733822",
    "us-east-2": "404615174143",
    "us-west-1": "632365934929",
    "us-west-2": "174872318107",
    "eu-west-1": "685385470294",
    "eu-central-1": "664544806723",
    "ap-southeast-1": "475088953585",
    "ap-southeast-2": "712309505854",
    "ap-northeast-1": "351501993468",
    "ap-south-1": "991648021394",
    "ca-central-1": "469771592824",
}


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteAlgorithm is rejected with ValidationException while the algorithm is still validating
    (AlgorithmStatus "Pending"), and succeeds once validation completes even with a Completed
    ModelPackage referencing it, because that reference is a metadata copy, not a live dependency.
    """
    account = _BUILTIN_ALGO_ACCOUNT_BY_REGION.get(ctx.region)
    if account is None:
        raise AssertionError(
            f"no known built-in-algorithm ECR registry account for region {ctx.region}"
        )
    training_image = f"{account}.dkr.ecr.{ctx.region}.amazonaws.com/kmeans:1"

    sm = ctx.client("sagemaker")
    algo_name = ctx.unique_name("sim2real-algo-")
    mp_name = ctx.unique_name("sim2real-mp-")
    bucket, key = _create_model_artifact(ctx)

    sm.create_algorithm(
        AlgorithmName=algo_name,
        TrainingSpecification={
            "TrainingImage": training_image,

            "SupportedTrainingInstanceTypes": ["ml.m5.large"],
            "TrainingChannels": [
                {
                    "Name": "training",
                    "SupportedContentTypes": ["text/csv"],
                    "SupportedInputModes": ["File"],
                }
            ],
        },
        InferenceSpecification={
            "Containers": [{"Image": training_image}],
            "SupportedContentTypes": ["text/csv"],
            "SupportedResponseMIMETypes": ["text/csv"],
            "SupportedRealtimeInferenceInstanceTypes": ["ml.t2.medium"],
            "SupportedTransformInstanceTypes": ["ml.m5.large"],
        },
        Tags=[{"Key": "sim2real-owner", "Value": "behavioral-suite"}],
    )
    ctx.on_cleanup(lambda: _safe_delete_algorithm(sm, algo_name))

    # Break exactly one thing: try to delete the algorithm while it is still
    # validating the referenced image. CreateAlgorithm leaves it in a
    # not-yet-terminal status (measured: "Pending") for well over a minute, so
    # the check opens this window itself and uses it immediately.
    described = sm.describe_algorithm(AlgorithmName=algo_name)
    status = described["AlgorithmStatus"]
    assert status in ("Pending", "InProgress"), (
        f"expected {algo_name} to still be validating right after CreateAlgorithm, "
        f"got AlgorithmStatus {status!r}"
    )
    code, message = _error_code_and_message(
        lambda: sm.delete_algorithm(AlgorithmName=algo_name)
    )
    assert code == "ValidationException", f"expected ValidationException, got {code}: {message}"
    # Validation can advance from Pending to InProgress between the read above and the
    # delete, so the refusal names whichever of the two statuses the algorithm is in.
    expected_inflight = {
        f"Cannot delete Algorithm in {inflight} status." for inflight in ("Pending", "InProgress")
    }
    assert message in expected_inflight, (
        f"expected one of the in-progress refusals {sorted(expected_inflight)!r}, got {message!r}"
    )
    # Effect absent: the algorithm was NOT deleted.
    described_again = sm.describe_algorithm(AlgorithmName=algo_name)
    assert described_again["AlgorithmName"] == algo_name, (
        f"expected {algo_name} to still exist after the rejected delete, "
        f"got {described_again.get('AlgorithmName')!r}"
    )

    _wait_for_algorithm_completed(sm, algo_name)

    # Positive control, same file: once validation completes, register a
    # ModelPackage that references this algorithm by name, then confirm
    # DeleteAlgorithm succeeds anyway (the reference does not block it).
    sm.create_model_package(
        ModelPackageName=mp_name,
        SourceAlgorithmSpecification={
            "SourceAlgorithms": [
                {
                    "AlgorithmName": algo_name,
                    "ModelDataUrl": f"s3://{bucket}/{key}",
                }
            ]
        },
        Tags=[{"Key": "sim2real-owner", "Value": "behavioral-suite"}],
    )
    ctx.on_cleanup(lambda: _safe_delete_model_package(sm, mp_name))

    sm.delete_algorithm(AlgorithmName=algo_name)
    code_after, message_after = _error_code_and_message(
        lambda: sm.describe_algorithm(AlgorithmName=algo_name)
    )
    # Empirically, DescribeAlgorithm on an algorithm that no longer exists
    # surfaces as ValidationException rather than the generic ResourceNotFound
    # used elsewhere in the SageMaker API.
    assert code_after == "ValidationException", (
        f"expected ValidationException, got {code_after}: {message_after}"
    )
    expected_gone = f"Algorithm arn:aws:sagemaker:{ctx.region}:{ctx.account}:algorithm/{algo_name} does not exist."
    assert message_after == expected_gone, (
        f"expected the deleted-algorithm refusal {expected_gone!r}, got {message_after!r}"
    )


# ===== helpers =====
def _error_code_and_message(fn):
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(
        f"expected the call to be rejected, but it succeeded and returned {result!r}"
    )


def _safe_delete_model_package(sm, name):
    try:
        sm.delete_model_package(ModelPackageName=name)
    except ClientError as exc:
        error = exc.response["Error"]
        if error["Code"] != "ValidationException" or "does not exist" not in error.get("Message", ""):
            raise


def _safe_delete_algorithm(sm, name):
    try:
        sm.delete_algorithm(AlgorithmName=name)
    except ClientError as exc:
        error = exc.response["Error"]
        if error["Code"] != "ValidationException" or "does not exist" not in error.get("Message", ""):
            raise


def _create_model_artifact(ctx):
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-algo-mp-").lower().replace("_", "-")
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(
            Bucket=bucket,
            CreateBucketConfiguration={"LocationConstraint": ctx.region},
        )
    ctx.on_cleanup(lambda: s3.delete_bucket(Bucket=bucket))
    key = "model.tar.gz"
    s3.put_object(Bucket=bucket, Key=key, Body=b"sim2real-placeholder-model-artifact")
    ctx.on_cleanup(lambda: s3.delete_object(Bucket=bucket, Key=key))
    return bucket, key


def _wait_for_algorithm_completed(sm, algo_name, *, timeout_s=180.0, interval_s=5.0):
    import time

    deadline = time.monotonic() + timeout_s
    last_status = None
    while time.monotonic() < deadline:
        described = sm.describe_algorithm(AlgorithmName=algo_name)
        last_status = described["AlgorithmStatus"]
        if last_status == "Completed":
            return described
        if last_status == "Failed":
            raise AssertionError(
                f"algorithm {algo_name} failed validation: "
                f"{described.get('AlgorithmStatusDetails')}"
            )
        time.sleep(interval_s)
    raise AssertionError(
        f"algorithm {algo_name} never reached Completed within {timeout_s}s "
        f"(last status: {last_status})"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
