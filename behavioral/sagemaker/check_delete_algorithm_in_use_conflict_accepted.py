"""delete-algorithm-in-use-conflict-accepted."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "delete-algorithm-in-use-conflict-accepted"
GROUP = "error-semantics"
SERVICES = ["sagemaker"]

# SageMaker's own built-in-algorithm ECR images are publicly pullable by any account, so
# referencing one (instead of a made-up image URI/account) lets CreateAlgorithm's real
# registry-access check succeed without pushing a private image. Per-region "1P algorithms"
# registry account for the kmeans/pca/linear-learner family.
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


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DeleteAlgorithm succeeds while a ModelPackage's SourceAlgorithmSpecification still
    references the algorithm: the algorithm disappears from lookups, and the ModelPackage is
    untouched and still names it."""
    account = _BUILTIN_ALGO_ACCOUNT_BY_REGION.get(ctx.region)
    if account is None:
        raise AssertionError(
            f"no known built-in-algorithm ECR registry account for region {ctx.region}"
        )
    training_image = f"{account}.dkr.ecr.{ctx.region}.amazonaws.com/linear-learner:1"

    sm = ctx.client("sagemaker")
    algo_name = ctx.unique_name("sim2real-algo-")
    mp_name = ctx.unique_name("sim2real-mp-")

    training_spec = {
        "TrainingImage": training_image,
        "SupportedTrainingInstanceTypes": ["ml.m5.large"],
        "TrainingChannels": [
            {
                "Name": "train",
                "SupportedContentTypes": ["text/csv"],
                "SupportedInputModes": ["File"],
            }
        ],
    }
    inference_spec = {
        "Containers": [{"Image": training_image}],
        "SupportedContentTypes": ["text/csv"],
        "SupportedResponseMIMETypes": ["text/csv"],
        "SupportedRealtimeInferenceInstanceTypes": ["ml.t2.medium"],
        "SupportedTransformInstanceTypes": ["ml.m5.large"],
    }
    sm.create_algorithm(
        AlgorithmName=algo_name,
        TrainingSpecification=training_spec,
        InferenceSpecification=inference_spec,
    )
    ctx.on_cleanup(lambda: _delete_algorithm_quiet(sm, algo_name))
    _wait_for_algorithm_completed(sm, algo_name)

    sm.create_model_package(
        ModelPackageName=mp_name,
        SourceAlgorithmSpecification={"SourceAlgorithms": [{"AlgorithmName": algo_name}]},
    )
    ctx.on_cleanup(lambda: _delete_model_package_quiet(sm, mp_name))

    # DeleteAlgorithm is NOT blocked by the ModelPackage's reference: it is a metadata
    # copy, not a live dependency.
    sm.delete_algorithm(AlgorithmName=algo_name)

    # effect present: the algorithm is gone from lookups after the (unblocked) delete.
    code_after, message_after = _error_code_and_message(
        lambda: sm.describe_algorithm(AlgorithmName=algo_name)
    )
    assert code_after == "ValidationException", (
        f"expected the deleted algorithm to 404 as ValidationException, got {code_after}: "
        f"{message_after!r}"
    )
    expected_gone = f"Algorithm arn:aws:sagemaker:{ctx.region}:{ctx.account}:algorithm/{algo_name} does not exist."
    assert message_after == expected_gone, (
        f"expected the deleted-algorithm refusal {expected_gone!r}, got {message_after!r}"
    )

    # the ModelPackage that referenced it is untouched: still describable, still naming
    # the (now-deleted) algorithm in its stored SourceAlgorithmSpecification.
    mp_described = sm.describe_model_package(ModelPackageName=mp_name)
    assert mp_described["ModelPackageName"] == mp_name, (
        f"expected the model package to still be describable, got {mp_described}"
    )
    referenced_algo = mp_described["SourceAlgorithmSpecification"]["SourceAlgorithms"][0][
        "AlgorithmName"
    ]
    assert referenced_algo == algo_name, (
        f"expected the model package to still name the deleted algorithm {algo_name}, "
        f"got {referenced_algo}"
    )


# ===== helpers =====
def _error_code_and_message(fn):
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(
        f"expected the call to be rejected, but it succeeded and returned {result!r}"
    )


def _delete_algorithm_quiet(sm, name: str) -> None:
    from botocore.exceptions import ClientError

    try:
        sm.delete_algorithm(AlgorithmName=name)
    except ClientError as e:
        if not _is_not_found(e):
            raise


def _delete_model_package_quiet(sm, name: str) -> None:
    from botocore.exceptions import ClientError

    try:
        sm.delete_model_package(ModelPackageName=name)
    except ClientError as e:
        if not _is_not_found(e):
            raise


def _is_not_found(e) -> bool:
    """SageMaker reports an already-deleted algorithm or model package as ValidationException."""
    error = e.response["Error"]
    message = error.get("Message", "").lower()
    return error.get("Code") == "ValidationException" and ("does not exist" in message or "not found" in message)


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
