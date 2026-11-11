"""execute-sampling-operation-session-name-constraints-rejected."""

from __future__ import annotations

from botocore.config import Config
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "execute-sampling-operation-session-name-constraints-rejected"
GROUP = "sampling-operations"
SERVICES = ["sagemakertrainingsessionruntime"]

_SAMPLE_CONFIG = {
    "sample": {
        "prompt": {"chunks": [{"tokens": [1, 2, 3], "type": "encoded_text"}]},
        "numSamples": 1,
        "samplingParams": {"maxTokens": 512},
    }
}


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
    """ExecuteSamplingOperation's trainingSessionName enforces its pattern and its 64-char
    length ceiling before any resource lookup, each with the model's own message."""
    runtime = _client(ctx)

    bad_char_name = ctx.unique_name("sim2real_sagemaker_tsr_")
    code, message = _error(
        lambda: runtime.execute_sampling_operation(
            trainingSessionName=bad_char_name, operationConfig=_SAMPLE_CONFIG
        )
    )
    assert code == "ValidationException", f"expected ValidationException, got {code}: {message!r}"
    expected = (
        f"1 validation error detected: Value '{bad_char_name}' at 'trainingSessionName' failed "
        "to satisfy constraint: Member must satisfy regular expression pattern: [a-zA-Z0-9-]+"
    )
    assert message == expected, f"expected {expected!r}, got {message!r}"

    too_long_name = "s" * 65
    code, message = _error(
        lambda: runtime.execute_sampling_operation(
            trainingSessionName=too_long_name, operationConfig=_SAMPLE_CONFIG
        )
    )
    assert code == "ValidationException", f"expected ValidationException, got {code}: {message!r}"
    expected = (
        f"1 validation error detected: Value '{too_long_name}' at 'trainingSessionName' failed "
        "to satisfy constraint: Member must have length less than or equal to 64"
    )
    assert message == expected, f"expected {expected!r}, got {message!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
