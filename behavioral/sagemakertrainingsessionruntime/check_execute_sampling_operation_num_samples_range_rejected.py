"""execute-sampling-operation-num-samples-range-rejected."""

from __future__ import annotations

from botocore.config import Config
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "execute-sampling-operation-num-samples-range-rejected"
GROUP = "sampling-operations"
SERVICES = ["sagemakertrainingsessionruntime"]


def _client(ctx):
    return ctx.client(
        "sagemakertrainingsessionruntime",
        config=Config(use_dualstack_endpoint=True, parameter_validation=False),
    )


def _error(fn):
    """(Error.Code, Error.Message) of the ClientError fn() raises; an unexpected success fails."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


def _sample(num_samples):
    return {
        "sample": {
            "prompt": {"chunks": [{"tokens": [1, 2, 3], "type": "encoded_text"}]},
            "numSamples": num_samples,
            "samplingParams": {"maxTokens": 512},
        }
    }


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """SampleConfig.numSamples is refused with ValidationException on both sides of its
    1-1000 range, a boundary distinct from the sibling samplingParams.maxTokens range."""
    runtime = _client(ctx)
    name = ctx.unique_name("sim2real-sagemaker-tsr-")

    code, message = _error(
        lambda: runtime.execute_sampling_operation(
            trainingSessionName=name, operationConfig=_sample(0)
        )
    )
    assert code == "ValidationException", f"expected ValidationException, got {code}: {message!r}"
    expected = (
        "1 validation error detected: Value '0' at 'operationConfig.sample.numSamples' "
        "failed to satisfy constraint: Member must have value greater than or equal to 1"
    )
    assert message == expected, f"expected {expected!r}, got {message!r}"

    code, message = _error(
        lambda: runtime.execute_sampling_operation(
            trainingSessionName=name, operationConfig=_sample(1001)
        )
    )
    assert code == "ValidationException", f"expected ValidationException, got {code}: {message!r}"
    expected = (
        "1 validation error detected: Value '1001' at 'operationConfig.sample.numSamples' "
        "failed to satisfy constraint: Member must have value less than or equal to 1000"
    )
    assert message == expected, f"expected {expected!r}, got {message!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
