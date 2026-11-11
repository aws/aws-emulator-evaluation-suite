"""algorithm-lifecycle-create-describe-delete."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "algorithm-lifecycle-create-describe-delete"
GROUP = "state-machine"
SERVICES = ["sagemaker"]

# SageMaker's own built-in XGBoost algorithm image is publicly pullable, in-region, in
# every commercial region without any push/docker tooling, so it is a real,
# always-resolvable TrainingImage — unlike a placeholder ECR path, which CreateAlgorithm
# rejects outright when its embedded region doesn't match the caller's region ("Cross-
# region ECR image pulls are not allowed").
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


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """An unreferenced Algorithm goes from created to describable, then after delete raises
    ValidationException "does not exist" on describe and on any mutation.
    """
    sm = ctx.client("sagemaker")
    name = ctx.unique_name("sim2real-algo-")

    registry_id = _XGBOOST_REGISTRY_BY_REGION.get(ctx.region)
    if registry_id is None:
        raise AssertionError(f"no known built-in XGBoost algorithm registry id for region {ctx.region!r}")
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
        AlgorithmDescription="sim2real behavioral check algorithm",
        TrainingSpecification=training_spec,
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )
    algorithm_arn = create_resp["AlgorithmArn"]
    ctx.on_cleanup(lambda: _delete_algorithm_ignore(sm, name))

    # No ValidationSpecification was supplied, so AlgorithmStatus settles on Completed
    # without a real validation training job ever running.
    status = _poll_until_terminal(sm, name, timeout_s=120)
    assert status == "Completed", f"expected AlgorithmStatus=Completed, got {status!r}"

    desc = sm.describe_algorithm(AlgorithmName=name)
    assert desc["AlgorithmArn"] == algorithm_arn, (
        f"expected AlgorithmArn={algorithm_arn!r}, got {desc.get('AlgorithmArn')!r}"
    )
    assert desc["TrainingSpecification"]["TrainingImage"] == training_image, (
        f"expected TrainingImage={training_image!r}, "
        f"got {desc['TrainingSpecification'].get('TrainingImage')!r}"
    )

    sm.delete_algorithm(AlgorithmName=name)

    describe_err = _client_error(lambda: sm.describe_algorithm(AlgorithmName=name))
    assert describe_err["Code"] == "ValidationException", (
        f"expected ValidationException from DescribeAlgorithm after delete, got {describe_err!r}"
    )
    expected_describe = f"Algorithm {algorithm_arn} does not exist."
    assert describe_err["Message"] == expected_describe, (
        f"expected message {expected_describe!r}, got {describe_err.get('Message')!r}"
    )

    # A mutation on the dead id must also fail, not just a read.
    tag_err = _client_error(lambda: sm.add_tags(ResourceArn=algorithm_arn, Tags=[{"Key": "k", "Value": "v"}]))
    assert tag_err["Code"] == "ValidationException", (
        f"expected ValidationException from AddTags on a deleted algorithm, got {tag_err!r}"
    )
    expected_tag = f"Algorithm {algorithm_arn} does not exist."
    assert tag_err["Message"] == expected_tag, (
        f"expected message {expected_tag!r}, got {tag_err.get('Message')!r}"
    )


# ===== helpers =====
def _client_error(fn):
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _poll_until_terminal(sm, name: str, timeout_s: float = 120.0) -> str:
    """AlgorithmStatus settling (even with no real validation job) is asynchronous; poll
    until it reaches a terminal state instead of asserting the first response."""
    deadline = time.monotonic() + timeout_s
    status = sm.describe_algorithm(AlgorithmName=name)["AlgorithmStatus"]
    while status not in ("Completed", "Failed"):
        if time.monotonic() > deadline:
            raise AssertionError(
                f"AlgorithmStatus for {name} did not settle within {timeout_s}s, last saw {status!r}"
            )
        time.sleep(2)
        status = sm.describe_algorithm(AlgorithmName=name)["AlgorithmStatus"]
    return status


def _delete_algorithm_ignore(sm, name: str) -> None:
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
