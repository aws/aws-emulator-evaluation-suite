"""execute-sampling-operation-config-union-member-count."""

from __future__ import annotations

from botocore.config import Config
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "execute-sampling-operation-config-union-member-count"
GROUP = "sampling-operations"
SERVICES = ["sagemakertrainingsessionruntime"]

_SAMPLE = {
    "prompt": {"chunks": [{"tokens": [1, 2, 3], "type": "encoded_text"}]},
    "numSamples": 1,
    "samplingParams": {"maxTokens": 512},
}
_COMPUTE_LOGPROBS = {"prompt": {"chunks": [{"tokens": [1, 2, 3], "type": "encoded_text"}]}}


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


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """operationConfig's "exactly one member" contract is enforced when zero members are set,
    but not when two are: the service validates and runs "sample" and ignores the rest."""
    runtime = _client(ctx)
    name = ctx.unique_name("sim2real-sagemaker-tsr-")

    code, message = _error(
        lambda: runtime.execute_sampling_operation(trainingSessionName=name, operationConfig={})
    )
    assert code == "ValidationException", f"expected ValidationException, got {code}: {message!r}"
    expected = "operationConfig must contain exactly one of: sample, computeLogprobs, loadWeightsForSampling"
    assert message == expected, f"expected {expected!r}, got {message!r}"

    code, message = _error(
        lambda: runtime.execute_sampling_operation(
            trainingSessionName=name,
            operationConfig={"sample": _SAMPLE, "computeLogprobs": _COMPUTE_LOGPROBS},
        )
    )
    assert code == "ResourceNotFoundException", (
        f"operationConfig with both sample and computeLogprobs set was expected to proceed to "
        f"the session lookup (ignoring the documented 'exactly one' contract), got {code}: {message!r}"
    )
    expected = f"Session not found: {name}-{ctx.account}-{ctx.region}"
    assert message == expected, f"expected {expected!r}, got {message!r}"

    broken_sample = dict(_SAMPLE, samplingParams={"maxTokens": 1})
    code, message = _error(
        lambda: runtime.execute_sampling_operation(
            trainingSessionName=name,
            operationConfig={"sample": broken_sample, "computeLogprobs": _COMPUTE_LOGPROBS},
        )
    )
    assert code == "ValidationException", (
        f"a broken 'sample' member alongside a valid 'computeLogprobs' one was expected to "
        f"surface sample's own validation error, got {code}: {message!r}"
    )
    expected = (
        "1 validation error detected: Value '1' at "
        "'operationConfig.sample.samplingParams.maxTokens' failed to satisfy constraint: "
        "Member must have value greater than or equal to 512"
    )
    assert message == expected, f"expected {expected!r}, got {message!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
