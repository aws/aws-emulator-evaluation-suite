"""create-experiment-malformed-name-fails."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-experiment-malformed-name-fails"
GROUP = 'overly-permissive'
SERVICES = ['sagemaker']

def _error(fn):
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message", "")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateExperiment with a name containing spaces and punctuation fails with ValidationException
    and the exact pattern message, while a well-formed name on the same client is created."""
    sm = ctx.client("sagemaker")

    control_name = ctx.unique_name("sim2real-behav-experiment-")
    sm.create_experiment(ExperimentName=control_name)
    ctx.on_cleanup(lambda: sm.delete_experiment(ExperimentName=control_name))

    code, message = _error(
        lambda: sm.create_experiment(ExperimentName="behav invalid name!")
    )
    assert code == "ValidationException", code
    expected = (
        "1 validation error detected: Value 'behav invalid name!' at 'experimentName' failed to "
        "satisfy constraint: Member must satisfy regular expression pattern: "
        "[a-zA-Z0-9](-*[a-zA-Z0-9]){0,119}"
    )
    assert message == expected, f"expected message {expected!r}, got {message!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
