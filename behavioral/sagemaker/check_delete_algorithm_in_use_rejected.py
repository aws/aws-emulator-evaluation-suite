"""delete-algorithm-in-use-rejected."""
from __future__ import annotations

import time
from typing import Any, Callable

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "delete-algorithm-in-use-rejected"
GROUP = "overly-permissive"
SERVICES = ["sagemaker"]

# Registry account IDs for the SageMaker 1P built-in-algorithm ECR images. These images are
# publicly readable cross-account (AWS grants pull access to any customer account/role), so
# they let CreateAlgorithm's real "can this image actually be resolved" check succeed without
# us owning a private ECR repo of our own.
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


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx: Any) -> None:
    """DeleteAlgorithm on an Algorithm still in Pending/InProgress validation is rejected with
    ValidationException, and the same Algorithm deletes cleanly once Completed, so the refusal
    tracks the transient validation state."""
    account_id = _BUILTIN_ALGO_REGISTRY.get(ctx.region)
    if account_id is None:
        raise AssertionError(
            f"region {ctx.region} is not in the curated built-in-algorithm ECR registry "
            "map used by this check to source a real, resolvable image"
        )

    sm = ctx.client("sagemaker")
    image = f"{account_id}.dkr.ecr.{ctx.region}.amazonaws.com/knn:1"
    alg_name = ctx.unique_name("sim2real-alg-")
    sm.create_algorithm(
        AlgorithmName=alg_name,
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
        TrainingSpecification={
            "TrainingImage": image,
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
            "Containers": [{"Image": image}],
            "SupportedContentTypes": ["text/csv"],
            "SupportedResponseMIMETypes": ["text/csv"],
            "SupportedRealtimeInferenceInstanceTypes": ["ml.m5.large"],
            "SupportedTransformInstanceTypes": ["ml.m5.large"],
        },
    )
    ctx.on_cleanup(lambda: _delete_algorithm_quiet(sm, alg_name))

    # Negative: while the algorithm is still in Pending/InProgress validation, a delete
    # must be rejected rather than silently tearing the in-flight resource down.
    status = sm.describe_algorithm(AlgorithmName=alg_name)["AlgorithmStatus"]
    if status not in ("Pending", "InProgress"):
        raise AssertionError(
            f"algorithm reached {status!r} before the delete; validation finished before the "
            "in-progress refusal could be observed"
        )
    code, msg = _error_code_and_message(lambda: sm.delete_algorithm(AlgorithmName=alg_name))
    assert code == "ValidationException", f"expected ValidationException, got {code!r}: {msg}"
    # Validation can move from Pending to InProgress between the read and the delete, never back;
    # the message names the status at the delete.
    order = ("Pending", "InProgress")
    expected = {f"Cannot delete Algorithm in {s} status." for s in order[order.index(status):]}
    assert msg in expected, f"expected one of the exact ValidationException messages {expected}, got {msg!r}"

    # Effect-absence: the algorithm still exists and is describable.
    desc = sm.describe_algorithm(AlgorithmName=alg_name)
    assert desc["AlgorithmName"] == alg_name, (
        f"expected the rejected delete to leave {alg_name!r} describable, got {desc['AlgorithmName']!r}"
    )

    # Positive control: once validation completes, the same algorithm deletes cleanly.
    _wait_algorithm_completed(ctx, alg_name)
    sm.delete_algorithm(AlgorithmName=alg_name)
    code2, msg2 = _error_code_and_message(lambda: sm.describe_algorithm(AlgorithmName=alg_name))
    assert code2 == "ValidationException", f"expected deleted algorithm lookup to fail, got {code2!r}: {msg2}"
    assert msg2 == f"Algorithm {desc['AlgorithmArn']} does not exist.", (
        f"expected the exact ValidationException message AWS returns, got {msg2!r}"
    )


# ===== helpers =====

def _error_code_and_message(fn: Callable[[], Any]) -> tuple[str, str]:
    """Call fn(); return its (code, message). An unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")
    raise AssertionError(f"expected a rejection, but the call succeeded and returned {result!r}")


def _delete_algorithm_quiet(sm: Any, name: str) -> None:
    # Delete is refused while validation runs: retry that refusal, return once it is gone.
    deadline = time.monotonic() + 300.0
    while True:
        try:
            sm.delete_algorithm(AlgorithmName=name)
            return
        except ClientError as exc:
            error = exc.response["Error"]
            message = error.get("Message", "")
            if error.get("Code") != "ValidationException":
                raise
            if "does not exist" in message:
                return
            if not message.startswith("Cannot delete Algorithm in ") or time.monotonic() >= deadline:
                raise
        time.sleep(2)


def _wait_algorithm_completed(ctx: Any, name: str, timeout_s: float = 120.0, interval_s: float = 5.0) -> None:
    sm = ctx.client("sagemaker")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        status = sm.describe_algorithm(AlgorithmName=name)["AlgorithmStatus"]
        if status == "Completed":
            return
        if status == "Failed":
            raise AssertionError(f"algorithm {name} entered Failed while validating")
        time.sleep(interval_s)
    raise AssertionError(f"algorithm {name} did not reach Completed within {timeout_s}s")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)


