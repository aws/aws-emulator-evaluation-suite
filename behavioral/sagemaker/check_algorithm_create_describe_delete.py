"""algorithm-create-describe-delete."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "algorithm-create-describe-delete"
GROUP = "state-machine"
SERVICES = ["sagemaker"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateAlgorithm reaches AlgorithmStatus=Completed and DescribeAlgorithm 404s after delete."""
    sm = ctx.client("sagemaker")
    name = ctx.unique_name("sim2real-algo-")

    # CreateAlgorithm validates that the TrainingImage actually resolves to a real,
    # pullable image manifest — an empty/self-owned ECR repo with no pushed image isn't
    # enough, and pushing a real image needs docker tooling this harness doesn't have.
    # AWS's own built-in XGBoost algorithm image is publicly pullable by any account in
    # these regions, so it's a real, always-resolvable TrainingImage to point at.
    xgboost_registry_by_region = {
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
    registry_id = xgboost_registry_by_region.get(ctx.region)
    if registry_id is None:

        raise AssertionError(f"no known built-in XGBoost algorithm registry ID for region {ctx.region!r}")
    training_image = f"{registry_id}.dkr.ecr.{ctx.region}.amazonaws.com/sagemaker-xgboost:1.7-1"

    training_spec = {
        "TrainingImage": training_image,
        "SupportedTrainingInstanceTypes": ["ml.m5.large"],
        "TrainingChannels": [
            {
                "Name": "training",
                "SupportedContentTypes": ["text/csv"],
                "SupportedInputModes": ["File"],
            }
        ],
    }
    create_resp = sm.create_algorithm(
        AlgorithmName=name,
        TrainingSpecification=training_spec,
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )
    algorithm_arn = create_resp["AlgorithmArn"]
    ctx.on_cleanup(lambda: _ignore_not_found(lambda: sm.delete_algorithm(AlgorithmName=name)))

    # No ValidationSpecification was supplied, so AlgorithmStatus should settle on
    # Completed without ever running a real validation training job.
    status = _poll_until(
        lambda: sm.describe_algorithm(AlgorithmName=name)["AlgorithmStatus"],
        lambda s: s in ("Completed", "Failed"),
        timeout_s=120,
        interval_s=3,
    )
    assert status == "Completed", f"expected AlgorithmStatus=Completed, got {status}"

    described = sm.describe_algorithm(AlgorithmName=name)
    assert described["AlgorithmArn"] == algorithm_arn, (
        f"expected AlgorithmArn {algorithm_arn!r}, got {described['AlgorithmArn']!r}"
    )
    assert described["TrainingSpecification"]["TrainingImage"] == training_spec["TrainingImage"], (
        "expected DescribeAlgorithm to reflect the TrainingImage supplied at creation, got "
        f"{described['TrainingSpecification']['TrainingImage']!r}"
    )

    sm.delete_algorithm(AlgorithmName=name)

    # Unlike the newer lineage/pipeline resources, Algorithm predates the ResourceNotFound
    # shape convention: DescribeAlgorithm documents no resource-specific error at all, and
    # in practice a missing algorithm surfaces as ValidationException, not ResourceNotFound.
    describe_err = _client_error(lambda: sm.describe_algorithm(AlgorithmName=name))
    assert describe_err["Code"] == "ValidationException", f"expected ValidationException after delete, got {describe_err!r}"
    expected_describe = f"Algorithm {algorithm_arn} does not exist."
    assert describe_err["Message"] == expected_describe, (
        f"expected message {expected_describe!r}, got {describe_err.get('Message')!r}"
    )

    # The delete beat is proved gone, not just described as gone: a second mutation against
    # the same dead name must also be refused, the same way the independent read was.
    second_delete_err = _client_error(lambda: sm.delete_algorithm(AlgorithmName=name))
    assert second_delete_err["Code"] == "ValidationException", (
        f"expected a delete of an already-deleted algorithm to fail with ValidationException, "
        f"got {second_delete_err!r}"
    )
    expected_delete = f"Algorithm {algorithm_arn} does not exist."
    assert second_delete_err["Message"] == expected_delete, (
        f"expected message {expected_delete!r}, got {second_delete_err.get('Message')!r}"
    )


# ===== helpers =====
def _client_error(fn):
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _ignore_not_found(fn):
    try:
        fn()
    except ClientError as e:
        error = e.response["Error"]
        if error.get("Code") != "ValidationException" or "does not exist" not in error.get("Message", ""):
            raise


def _poll_until(probe, predicate, *, timeout_s: float, interval_s: float):
    deadline = time.monotonic() + timeout_s
    value = probe()
    while not predicate(value):
        if time.monotonic() >= deadline:
            raise AssertionError(f"condition not met within {timeout_s}s (last value: {value!r})")
        time.sleep(interval_s)
        value = probe()
    return value


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
