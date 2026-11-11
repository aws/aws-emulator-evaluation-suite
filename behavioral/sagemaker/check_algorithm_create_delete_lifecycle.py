"""algorithm-create-delete-lifecycle."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "algorithm-create-delete-lifecycle"
GROUP = "state-machine"
SERVICES = ["sagemaker"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Algorithm is created, transitions to a usable status, then delete removes it entirely."""
    sm = ctx.client("sagemaker")
    name = ctx.unique_name("sim2real-algo-")

    resp = sm.create_algorithm(
        AlgorithmName=name,
        AlgorithmDescription="sim2real behavioral fidelity check algorithm",
        TrainingSpecification=_minimal_training_spec(ctx),
    )
    arn = resp["AlgorithmArn"]

    cleaned = {"done": False}

    def _cleanup() -> None:
        if not cleaned["done"]:
            from botocore.exceptions import ClientError

            try:
                sm.delete_algorithm(AlgorithmName=name)
            except ClientError as err:
                error = err.response["Error"]
                if error.get("Code") != "ValidationException" or "does not exist" not in error.get("Message", ""):
                    raise

    ctx.on_cleanup(_cleanup)

    status = _poll_until(
        lambda: sm.describe_algorithm(AlgorithmName=name)["AlgorithmStatus"],
        lambda s: s in ("Completed", "Failed"),
        timeout_s=120.0,
        interval_s=3.0,
    )
    assert status == "Completed", f"algorithm did not become usable, status={status}"

    desc = sm.describe_algorithm(AlgorithmName=name)
    assert desc["AlgorithmArn"] == arn, f"expected AlgorithmArn={arn!r}, got {desc['AlgorithmArn']!r}"
    assert desc["AlgorithmName"] == name, f"expected AlgorithmName={name!r}, got {desc['AlgorithmName']!r}"

    sm.delete_algorithm(AlgorithmName=name)
    cleaned["done"] = True

    # Algorithm predates the ResourceNotFound shape convention: DescribeAlgorithm documents
    # no resource-specific error, and a missing algorithm surfaces as ValidationException.
    describe_err = _client_error(lambda: sm.describe_algorithm(AlgorithmName=name))
    assert describe_err["Code"] == "ValidationException", (
        f"expected ValidationException for describe of a deleted algorithm, got {describe_err!r}"
    )
    expected_describe = f"Algorithm {arn} does not exist."
    assert describe_err["Message"] == expected_describe, (
        f"expected message {expected_describe!r}, got {describe_err.get('Message')!r}"
    )


# ===== helpers =====
# Registry account IDs for the SageMaker 1P built-in XGBoost algorithm ECR image, which AWS
# grants public cross-account pull access to. CreateAlgorithm validates that TrainingImage
# resolves to a real, pullable image manifest, so a fabricated registry account is rejected
# before the algorithm is ever created.
_XGBOOST_REGISTRY_BY_REGION = {
    "us-east-1": "683313688378",
    "us-east-2": "257758044811",
    "us-west-1": "746614075791",
    "us-west-2": "246618743249",
    "eu-west-1": "685385470294",
    "eu-central-1": "813361260812",
    "ap-southeast-1": "121021644041",
    "ap-southeast-2": "783357654285",
    "ap-northeast-1": "501404015308",
    "ap-south-1": "720646828776",
}


def _minimal_training_spec(ctx) -> dict:
    registry_id = _XGBOOST_REGISTRY_BY_REGION.get(ctx.region)
    if registry_id is None:
        raise AssertionError(f"no known built-in XGBoost algorithm registry ID for region {ctx.region!r}")
    return {
        "TrainingImage": f"{registry_id}.dkr.ecr.{ctx.region}.amazonaws.com/sagemaker-xgboost:1.7-1",
        "SupportedTrainingInstanceTypes": ["ml.m5.large"],
        "TrainingChannels": [
            {
                "Name": "training",
                "SupportedContentTypes": ["text/csv"],
                "SupportedInputModes": ["File"],
            }
        ],
    }


def _client_error(fn):
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _poll_until(probe, predicate, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    value = None
    while time.monotonic() < deadline:
        value = probe()
        if predicate(value):
            return value
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last value: {value!r})")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
