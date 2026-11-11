"""algorithm-lifecycle-delete-when-unused."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "algorithm-lifecycle-delete-when-unused"
GROUP = "state-machine"
SERVICES = ["sagemaker"]

# Registry account IDs for the SageMaker 1P built-in-algorithm ECR images. These images are
# publicly readable cross-account (AWS grants pull access to any customer account), so they
# let CreateAlgorithm validate real, resolvable image access without us owning a private ECR
# repo of our own.
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


def _client_error(fn):
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """An Algorithm with no dependent model packages/training jobs can be deleted,
    transitioning to a fully removed state."""
    account_id = _BUILTIN_ALGO_REGISTRY.get(ctx.region)
    if account_id is None:
        raise AssertionError(
            f"region {ctx.region} is not in the curated built-in-algorithm ECR registry "
            "map used by this check to source a real, accessible training image"
        )

    sm = ctx.client("sagemaker")
    name = ctx.unique_name("sim2real-behav-algo-")

    create_resp = sm.create_algorithm(
        AlgorithmName=name,
        TrainingSpecification={
            "TrainingImage": f"{account_id}.dkr.ecr.{ctx.region}.amazonaws.com/knn:1",
            "SupportedTrainingInstanceTypes": ["ml.m5.large"],
            "TrainingChannels": [
                {
                    "Name": "train",
                    "SupportedContentTypes": ["text/csv"],
                    "SupportedInputModes": ["File"],
                }
            ],
        },
        Tags=[{"Key": "sim2real", "Value": "algorithm-lifecycle-delete-when-unused"}],
    )
    ctx.on_cleanup(lambda: _delete_algorithm_quiet(sm, name))
    assert create_resp["AlgorithmArn"].endswith(f"algorithm/{name}"), (
        f"expected AlgorithmArn to end with algorithm/{name}, got {create_resp['AlgorithmArn']!r}"
    )

    status = _poll_algorithm_status(sm, name, {"Completed", "Failed"}, timeout_s=60.0)
    assert status == "Completed", f"expected AlgorithmStatus=Completed, got {status!r}"

    sm.delete_algorithm(AlgorithmName=name)

    describe_err = _client_error(lambda: sm.describe_algorithm(AlgorithmName=name))
    assert describe_err["Code"] == "ValidationException", f"expected ValidationException after delete, got {describe_err!r}"
    expected_describe = f"Algorithm {create_resp['AlgorithmArn']} does not exist."
    assert describe_err["Message"] == expected_describe, (
        f"expected message {expected_describe!r}, got {describe_err.get('Message')!r}"
    )

    second_delete_err = _client_error(lambda: sm.delete_algorithm(AlgorithmName=name))
    assert second_delete_err["Code"] == "ValidationException", (
        f"expected a second delete of an already-deleted algorithm to also fail with "
        f"ValidationException (proving the id is genuinely dead, not just describe-flaky), "
        f"got {second_delete_err!r}"
    )
    expected_delete = f"Algorithm {create_resp['AlgorithmArn']} does not exist."
    assert second_delete_err["Message"] == expected_delete, (
        f"expected message {expected_delete!r}, got {second_delete_err.get('Message')!r}"
    )


# ===== helpers =====
def _poll_algorithm_status(sm, name: str, terminal_statuses, timeout_s: float = 60.0, interval_s: float = 3.0) -> str:
    deadline = time.monotonic() + timeout_s
    status = ""
    while time.monotonic() < deadline:
        status = sm.describe_algorithm(AlgorithmName=name)["AlgorithmStatus"]
        if status in terminal_statuses:
            return status
        time.sleep(interval_s)
    return status


def _delete_algorithm_quiet(sm, name: str) -> None:
    from botocore.exceptions import ClientError

    try:
        sm.delete_algorithm(AlgorithmName=name)
    except ClientError as err:
        error = err.response["Error"]
        if error.get("Code") != "ValidationException" or "does not exist" not in error.get("Message", ""):
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
